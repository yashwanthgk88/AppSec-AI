"""Jira REST API v3 client for syncing user stories and pushing security analysis."""

import logging
from base64 import b64encode
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class JiraClient:
    def __init__(self, base_url: str, email: str, api_token: str):
        self.base_url = base_url.rstrip("/")
        auth = b64encode(f"{email}:{api_token}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict:
        """Test the Jira connection."""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{self.base_url}/rest/api/3/myself", headers=self.headers)
                if resp.status_code == 200:
                    try:
                        user = resp.json()
                    except Exception:
                        return {"success": True, "message": "Connected successfully"}
                    return {"success": True, "message": f"Connected as {user.get('displayName', user.get('emailAddress'))}"}
                if resp.status_code == 401:
                    return {"success": False, "message": "Authentication failed. Check your email and API token."}
                if resp.status_code == 403:
                    return {"success": False, "message": "Access denied. The API token may lack required permissions."}
                return {"success": False, "message": f"Connection failed with status {resp.status_code}. Verify the Jira URL is correct."}
        except httpx.ConnectError:
            return {"success": False, "message": f"Cannot connect to {self.base_url}. Verify the URL is correct and reachable."}
        except httpx.TimeoutException:
            return {"success": False, "message": "Connection timed out. Check the Jira URL and your network."}
        except Exception as e:
            return {"success": False, "message": str(e)}

    async def get_projects(self) -> list[dict]:
        """Get all accessible Jira projects."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{self.base_url}/rest/api/3/project", headers=self.headers)
            if resp.status_code >= 400:
                # Try search endpoint as fallback
                resp = await client.get(
                    f"{self.base_url}/rest/api/3/project/search",
                    headers=self.headers,
                    params={"maxResults": 100}
                )
                if resp.status_code >= 400:
                    resp.raise_for_status()
                data = resp.json()
                return data.get("values", [])
            return resp.json()

    async def get_project_issues(self, project_id: str, issue_types: list[str] = None, max_results: int = 100) -> list[dict]:
        """Get user stories/issues from a Jira project."""
        # Build JQL query
        jql_parts = [f"project = {project_id}"]
        if issue_types:
            types_str = ", ".join(f'"{t}"' for t in issue_types)
            jql_parts.append(f"issuetype IN ({types_str})")
        jql = " AND ".join(jql_parts) + " ORDER BY created DESC"

        logger.info("Fetching issues with JQL: %s", jql)
        async with httpx.AsyncClient(timeout=60) as client:
            # Try the newer /search/jql endpoint first, fall back to /search
            resp = await client.get(
                f"{self.base_url}/rest/api/3/search/jql",
                headers=self.headers,
                params={
                    "jql": jql,
                    "maxResults": max_results,
                    "fields": "summary,description,issuetype,status,created,updated,customfield_*"
                }
            )

            # Fallback to /rest/api/3/search (POST) if the newer endpoint is not available
            if resp.status_code in (404, 405):
                logger.info("Falling back to /rest/api/3/search POST endpoint")
                resp = await client.post(
                    f"{self.base_url}/rest/api/3/search",
                    headers=self.headers,
                    json={
                        "jql": jql,
                        "maxResults": max_results,
                        "fields": ["summary", "description", "issuetype", "status", "created", "updated"]
                    }
                )

            # Fallback to v2 API if v3 fails
            if resp.status_code in (404, 405):
                logger.info("Falling back to /rest/api/2/search endpoint")
                resp = await client.post(
                    f"{self.base_url}/rest/api/2/search",
                    headers=self.headers,
                    json={
                        "jql": jql,
                        "maxResults": max_results,
                        "fields": ["summary", "description", "issuetype", "status", "created", "updated"]
                    }
                )

            if resp.status_code == 401:
                raise ValueError(
                    "Authentication failed. Please check your Jira credentials in Settings: "
                    "1) Verify the email matches your Atlassian account, "
                    "2) Generate a fresh API token at https://id.atlassian.net/manage-profile/security/api-tokens, "
                    "3) Ensure the token has not expired."
                )
            if resp.status_code == 403:
                raise ValueError(
                    f"Access denied to project '{project_id}'. Your Jira API token may not have "
                    f"permission to access this project. Check that the account has 'Browse Projects' permission."
                )
            if resp.status_code >= 400:
                logger.error("Jira search failed: %s - %s", resp.status_code, resp.text)
                try:
                    err = resp.json()
                    messages = err.get("errorMessages", [])
                    if messages:
                        raise ValueError(f"Jira error: {'; '.join(messages)}")
                except (ValueError):
                    raise
                except Exception:
                    pass
            resp.raise_for_status()
            data = resp.json()
            return data.get("issues", [])

    async def create_issue(self, project_key: str, summary: str, description: str,
                           issue_type: str = "Story", extra_fields: dict = None) -> dict:
        """Create a new Jira issue."""
        # Build ADF description
        adf_description = {
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": para}]}
                for para in description.split("\n") if para.strip()
            ]
        }
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": adf_description,
                "issuetype": {"name": issue_type},
                **(extra_fields or {})
            }
        }
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/rest/api/3/issue",
                json=payload,
                headers=self.headers,
            )
            if resp.status_code >= 400:
                logger.error("Jira create failed: %s - %s", resp.status_code, resp.text)
                resp.raise_for_status()
            data = resp.json()
            logger.info("Created Jira issue: %s", data.get("key"))
            return data

    async def get_issue(self, issue_key: str) -> dict:
        """Get issue details."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/rest/api/3/issue/{issue_key}",
                headers=self.headers,
                params={"fields": "*all"}
            )
            resp.raise_for_status()
            return resp.json()

    async def get_fields(self) -> list[dict]:
        """Get all fields including custom fields."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{self.base_url}/rest/api/3/field", headers=self.headers)
            resp.raise_for_status()
            return resp.json()

    async def find_custom_field_id(self, field_name: str) -> Optional[str]:
        """Find a custom field ID by its name (case-insensitive)."""
        fields = await self.get_fields()
        field_name_lower = field_name.lower()
        for field in fields:
            if field.get("name", "").lower() == field_name_lower:
                return field.get("id")
        return None

    async def update_issue(self, issue_key: str, fields: dict) -> dict:
        """Update issue fields."""
        payload = {"fields": fields}
        logger.info("Updating Jira issue %s with fields: %s", issue_key, list(fields.keys()))
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.put(
                f"{self.base_url}/rest/api/3/issue/{issue_key}",
                json=payload,
                headers=self.headers,
            )
            if resp.status_code >= 400:
                error_text = resp.text
                logger.error("Jira update failed for %s: %s - %s", issue_key, resp.status_code, error_text)
                try:
                    error_data = resp.json()
                    errors = error_data.get("errors", {})
                    error_messages = error_data.get("errorMessages", [])
                    error_details = []
                    if error_messages:
                        error_details.extend(error_messages)
                    if errors:
                        for field_id, msg in errors.items():
                            error_details.append(f"{field_id}: {msg}")
                    if error_details:
                        raise ValueError(f"Jira API error: {'; '.join(error_details)}")
                except ValueError:
                    raise
                except Exception:
                    pass
                resp.raise_for_status()
            logger.info("Updated Jira issue: %s", issue_key)
            return {"key": issue_key, "updated": True}

    def _build_abuse_cases_adf(self, abuse_cases: list[dict]) -> dict:
        """Build Atlassian Document Format content for abuse cases (securereq-ai format)."""
        content = []

        # Header
        content.append({
            "type": "heading",
            "attrs": {"level": 2},
            "content": [{"type": "text", "text": "Security Abuse Cases Analysis"}]
        })

        for i, ac in enumerate(abuse_cases, 1):
            # Get ID or generate one
            ac_id = ac.get('id', f'AC-{i:03d}')
            # Title - use 'threat' (securereq-ai format) or 'title'
            title = ac.get('threat', ac.get('title', 'Unknown Threat'))

            content.append({
                "type": "heading",
                "attrs": {"level": 3},
                "content": [{"type": "text", "text": f"{ac_id}: {title}"}]
            })

            # Description
            if ac.get("description"):
                content.append({
                    "type": "paragraph",
                    "content": [{"type": "text", "text": ac.get('description')}]
                })

            # Main details as bullet list
            items = []

            # Actor - use 'actor' (securereq-ai format) or 'threat_actor'
            actor = ac.get('actor', ac.get('threat_actor'))
            if actor:
                items.append({"type": "listItem", "content": [{"type": "paragraph", "content": [
                    {"type": "text", "text": "Threat Actor: ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": str(actor)}
                ]}]})

            # Attack Vector
            if ac.get('attack_vector'):
                items.append({"type": "listItem", "content": [{"type": "paragraph", "content": [
                    {"type": "text", "text": "Attack Vector: ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": ac.get('attack_vector')}
                ]}]})

            # STRIDE Category
            if ac.get('stride_category'):
                items.append({"type": "listItem", "content": [{"type": "paragraph", "content": [
                    {"type": "text", "text": "STRIDE Category: ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": ac.get('stride_category')}
                ]}]})

            if items:
                content.append({"type": "bulletList", "content": items})

            # Mitigations
            mitigations = ac.get("mitigations", [])
            if mitigations:
                content.append({
                    "type": "paragraph",
                    "content": [{"type": "text", "text": "Recommended Mitigations:", "marks": [{"type": "strong"}]}]
                })
                mitigation_items = [
                    {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text", "text": str(m)}]}]}
                    for m in mitigations if m
                ]
                if mitigation_items:
                    content.append({"type": "bulletList", "content": mitigation_items})

            content.append({"type": "rule"})

        # Footer
        content.append({
            "type": "paragraph",
            "content": [{"type": "text", "text": f"Generated by SecureReq AI | Total: {len(abuse_cases)} abuse cases", "marks": [{"type": "em"}]}]
        })

        return {"type": "doc", "version": 1, "content": content}

    def _build_security_requirements_adf(self, requirements: list[dict]) -> dict:
        """Build Atlassian Document Format content for security requirements (securereq-ai format)."""
        content = []

        # Header
        content.append({
            "type": "heading",
            "attrs": {"level": 2},
            "content": [{"type": "text", "text": "Security Requirements"}]
        })

        # List all requirements without priority grouping
        for req in requirements:
            # Requirement ID and text - use 'text' (securereq-ai format) or 'requirement'
            req_id = req.get('id', 'SR-XXX')
            req_text = req.get('text', req.get('requirement', ''))
            category = req.get('category', '')

            content.append({
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"[{req_id}] ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": req_text}
                ]
            })

            # Details as a sub-list
            detail_items = []

            if category:
                detail_items.append({"type": "listItem", "content": [{"type": "paragraph", "content": [
                    {"type": "text", "text": "Category: ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": category}
                ]}]})

            # Use 'details' (securereq-ai format) as the main implementation guidance
            details_text = req.get('details', req.get('implementation_guidance', req.get('rationale', '')))
            if details_text:
                detail_items.append({"type": "listItem", "content": [{"type": "paragraph", "content": [
                    {"type": "text", "text": "Implementation Details: ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": details_text}
                ]}]})

            if detail_items:
                content.append({"type": "bulletList", "content": detail_items})

        content.append({"type": "rule"})
        content.append({
            "type": "paragraph",
            "content": [{"type": "text", "text": f"Generated by SecureReq AI | Total: {len(requirements)} security requirements", "marks": [{"type": "em"}]}]
        })

        return {"type": "doc", "version": 1, "content": content}

    async def get_issue_editmeta(self, issue_key: str) -> dict:
        """Get edit metadata for an issue to see available fields."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/rest/api/3/issue/{issue_key}/editmeta",
                headers=self.headers,
            )
            resp.raise_for_status()
            return resp.json()

    def _build_abuse_cases_plaintext(self, abuse_cases: list[dict]) -> str:
        """Build plain text content for abuse cases (fallback for string fields)."""
        lines = ["=== Security Abuse Cases Analysis ===\n"]
        for i, ac in enumerate(abuse_cases, 1):
            ac_id = ac.get('id', f'AC-{i:03d}')
            title = ac.get('threat', ac.get('title', 'Unknown Threat'))
            lines.append(f"\n--- {ac_id}: {title} ---")
            if ac.get("description"):
                lines.append(ac["description"])
            actor = ac.get('actor', ac.get('threat_actor'))
            if actor:
                lines.append(f"Threat Actor: {actor}")
            if ac.get('attack_vector'):
                lines.append(f"Attack Vector: {ac['attack_vector']}")
            if ac.get('stride_category'):
                lines.append(f"STRIDE Category: {ac['stride_category']}")
            mitigations = ac.get("mitigations", [])
            if mitigations:
                lines.append("Mitigations:")
                for m in mitigations:
                    if m:
                        lines.append(f"  - {m}")
        lines.append(f"\nGenerated by SecureReq AI | Total: {len(abuse_cases)} abuse cases")
        return "\n".join(lines)

    def _build_security_requirements_plaintext(self, requirements: list[dict]) -> str:
        """Build plain text content for security requirements (fallback for string fields)."""
        lines = ["=== Security Requirements ===\n"]
        for req in requirements:
            req_id = req.get('id', 'SR-XXX')
            req_text = req.get('text', req.get('requirement', ''))
            category = req.get('category', '')
            lines.append(f"[{req_id}] {req_text}")
            if category:
                lines.append(f"  Category: {category}")
            details = req.get('details', req.get('implementation_guidance', req.get('rationale', '')))
            if details:
                lines.append(f"  Details: {details}")
            lines.append("")
        lines.append(f"Generated by SecureReq AI | Total: {len(requirements)} requirements")
        return "\n".join(lines)

    async def _resolve_field_id(self, field_value: Optional[str], default_name: str) -> Optional[str]:
        """Resolve a custom field setting to a field ID. Supports customfield_XXXXX or display name."""
        if not field_value:
            # Try default name
            return await self.find_custom_field_id(default_name)

        if field_value.startswith("customfield_"):
            return field_value

        # Try exact match first, then partial/fuzzy match
        field_id = await self.find_custom_field_id(field_value)
        if field_id:
            return field_id

        # Try common variations
        variations = [
            field_value,
            field_value.lower(),
            field_value.replace("_", " "),
            field_value.replace("-", " "),
        ]
        fields = await self.get_fields()
        for field in fields:
            fname = field.get("name", "").lower()
            for v in variations:
                if v.lower() == fname or v.lower() in fname:
                    logger.info("Fuzzy matched field '%s' -> '%s' (%s)", field_value, field["name"], field["id"])
                    return field["id"]
        return None

    async def _get_field_schema_type(self, field_id: str) -> Optional[str]:
        """Get the schema type of a field (string, doc, etc.)."""
        try:
            fields = await self.get_fields()
            for f in fields:
                if f.get("id") == field_id:
                    return f.get("schema", {}).get("type")
        except Exception:
            pass
        return None

    async def _resolve_editable_field(self, issue_key: str, field_setting: Optional[str], default_name: str) -> Optional[str]:
        """
        Resolve the correct custom field ID by checking what's actually editable
        on the target issue. This handles team-managed vs company-managed projects
        which can have different field IDs for the same field name.
        """
        try:
            meta = await self.get_issue_editmeta(issue_key)
            editable = meta.get("fields", {})
        except Exception:
            editable = {}

        # If a specific field ID was configured, check if it's editable on this issue
        if field_setting and field_setting.startswith("customfield_"):
            if field_setting in editable:
                return field_setting
            logger.info("Configured field %s not editable on %s, searching by name '%s'...", field_setting, issue_key, default_name)

        # Always search editable fields by the default display name (e.g. "Abuse cases")
        search_name = default_name.lower()
        for fid, info in editable.items():
            if not fid.startswith("customfield_"):
                continue
            fname = info.get("name", "").lower()
            if fname == search_name or search_name in fname or fname in search_name:
                logger.info("Resolved editable field '%s' -> %s (%s) on %s", default_name, fid, info.get("name"), issue_key)
                return fid

        # Last resort: fall back to global field lookup (may not be editable)
        logger.warning("No editable field matching '%s' found on %s, falling back to global lookup", default_name, issue_key)
        return await self._resolve_field_id(field_setting, default_name)

    async def publish_analysis_to_issue(
        self,
        issue_key: str,
        analysis: dict,
        abuse_cases_field: Optional[str] = None,
        security_req_field: Optional[str] = None
    ) -> dict:
        """
        Publish analysis results directly into the Jira issue custom fields.

        Auto-detects the correct field IDs from the issue's editable fields,
        then tries ADF first, falling back to plain text.
        """
        abuse_cases = analysis.get("abuse_cases", [])
        requirements = analysis.get("security_requirements", [])

        fields_to_update = {}
        updated_field_names = []
        missing_fields = []

        logger.info("Resolving custom fields for issue %s...", issue_key)

        # Resolve field IDs from what's actually editable on this issue
        abuse_field_id = await self._resolve_editable_field(issue_key, abuse_cases_field, "Abuse cases")
        req_field_id = await self._resolve_editable_field(issue_key, security_req_field, "Security requirements")

        if abuse_field_id:
            logger.info("Found 'Abuse cases' custom field: %s", abuse_field_id)
        else:
            logger.warning("Custom field 'Abuse cases' not found or not editable on %s", issue_key)
            missing_fields.append(abuse_cases_field or "Abuse cases")

        if req_field_id:
            logger.info("Found 'Security requirements' custom field: %s", req_field_id)
        else:
            logger.warning("Custom field 'Security requirements' not found or not editable on %s", issue_key)
            missing_fields.append(security_req_field or "Security requirements")

        # Build ADF content (preferred format)
        if abuse_field_id and abuse_cases:
            fields_to_update[abuse_field_id] = self._build_abuse_cases_adf(abuse_cases)
            updated_field_names.append("Abuse cases")

        if req_field_id and requirements:
            fields_to_update[req_field_id] = self._build_security_requirements_adf(requirements)
            updated_field_names.append("Security requirements")

        if not fields_to_update:
            if missing_fields:
                error_msg = (
                    f"Custom fields not found or not editable in Jira: {', '.join(missing_fields)}. "
                    f"Please check: 1) The field names/IDs in Settings match exactly what's in Jira, "
                    f"2) Fields are added to the issue's edit screen in Project Settings > Fields."
                )
            else:
                error_msg = "No analysis data to publish (no abuse cases or security requirements found in the analysis)."
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Try ADF first, fall back to plain text if it fails
        try:
            result = await self.update_issue(issue_key, fields_to_update)
        except (ValueError, Exception) as first_error:
            logger.warning("ADF publish failed: %s. Retrying with plain text...", first_error)
            plain_fields = {}
            if abuse_field_id and abuse_cases:
                plain_fields[abuse_field_id] = self._build_abuse_cases_plaintext(abuse_cases)
            if req_field_id and requirements:
                plain_fields[req_field_id] = self._build_security_requirements_plaintext(requirements)
            if plain_fields:
                result = await self.update_issue(issue_key, plain_fields)
            else:
                raise first_error

        logger.info("Updated Jira issue %s with fields: %s", issue_key, updated_field_names)
        return result

    @staticmethod
    def extract_description_text(description: dict | str | None) -> str:
        """Extract plain text from Jira's ADF description format."""
        if not description:
            return ""
        if isinstance(description, str):
            return description

        # Handle ADF format
        def extract_text(node: dict) -> str:
            if node.get("type") == "text":
                return node.get("text", "")
            content = node.get("content", [])
            return " ".join(extract_text(c) for c in content if isinstance(c, dict))

        return extract_text(description).strip()
