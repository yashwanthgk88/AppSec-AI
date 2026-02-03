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
                    user = resp.json()
                    return {"success": True, "message": f"Connected as {user.get('displayName', user.get('emailAddress'))}"}
                return {"success": False, "message": f"Authentication failed: {resp.status_code}"}
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
            resp = await client.get(
                f"{self.base_url}/rest/api/3/search/jql",
                headers=self.headers,
                params={
                    "jql": jql,
                    "maxResults": max_results,
                    "fields": "summary,description,issuetype,status,created,updated,customfield_*"
                }
            )
            if resp.status_code >= 400:
                logger.error("Jira search failed: %s - %s", resp.status_code, resp.text)
            resp.raise_for_status()
            data = resp.json()
            return data.get("issues", [])

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

    async def publish_analysis_to_issue(
        self,
        issue_key: str,
        analysis: dict,
        abuse_cases_field: Optional[str] = None,
        security_req_field: Optional[str] = None
    ) -> dict:
        """
        Publish analysis results directly into the Jira issue custom fields.

        Uses Atlassian Document Format (ADF) for rich text custom fields.
        Matches the implementation from securereq-ai project.

        Args:
            issue_key: Jira issue key (e.g., PROJ-123)
            analysis: Analysis data with abuse_cases and security_requirements
            abuse_cases_field: Custom field ID (customfield_XXXXX) or display name
            security_req_field: Custom field ID (customfield_XXXXX) or display name
        """
        abuse_cases = analysis.get("abuse_cases", [])
        requirements = analysis.get("security_requirements", [])

        fields_to_update = {}
        updated_field_names = []
        missing_fields = []

        # Auto-discover custom field IDs by name if not provided as customfield_XXXXX
        logger.info("Looking for custom fields in Jira...")

        # Resolve abuse cases field
        if abuse_cases_field and abuse_cases_field.startswith("customfield_"):
            abuse_field_id = abuse_cases_field
        else:
            field_name = abuse_cases_field or "Abuse cases"
            abuse_field_id = await self.find_custom_field_id(field_name)

        # Resolve security requirements field
        if security_req_field and security_req_field.startswith("customfield_"):
            req_field_id = security_req_field
        else:
            field_name = security_req_field or "Security requirements"
            req_field_id = await self.find_custom_field_id(field_name)

        if abuse_field_id:
            logger.info("Found 'Abuse cases' custom field: %s", abuse_field_id)
        else:
            logger.warning("Custom field 'Abuse cases' not found in Jira")
            missing_fields.append("Abuse cases")

        if req_field_id:
            logger.info("Found 'Security requirements' custom field: %s", req_field_id)
        else:
            logger.warning("Custom field 'Security requirements' not found in Jira")
            missing_fields.append("Security requirements")

        # Get editmeta to check field editability
        try:
            editmeta = await self.get_issue_editmeta(issue_key)
            available_fields = editmeta.get("fields", {})
            logger.info("Editable fields for %s: %s", issue_key, list(available_fields.keys()))
        except Exception as e:
            logger.warning("Could not get editmeta for %s: %s", issue_key, e)
            available_fields = {}

        # Populate "Abuse cases" custom field with ADF content
        if abuse_field_id and abuse_cases:
            if abuse_field_id not in available_fields:
                logger.warning("Field %s exists but may not be editable for issue %s", abuse_field_id, issue_key)

            logger.info("Building ADF content for Abuse cases field (%d cases)", len(abuse_cases))
            adf_content = self._build_abuse_cases_adf(abuse_cases)
            fields_to_update[abuse_field_id] = adf_content
            updated_field_names.append("Abuse cases")

        # Populate "Security requirements" custom field with ADF content
        if req_field_id and requirements:
            if req_field_id not in available_fields:
                logger.warning("Field %s exists but may not be editable for issue %s", req_field_id, issue_key)

            logger.info("Building ADF content for Security requirements field (%d requirements)", len(requirements))
            adf_content = self._build_security_requirements_adf(requirements)
            fields_to_update[req_field_id] = adf_content
            updated_field_names.append("Security requirements")

        if not fields_to_update:
            if missing_fields:
                error_msg = (
                    f"Custom fields not found in Jira: {', '.join(missing_fields)}. "
                    f"Please create these custom text fields in your Jira project settings: "
                    f"Project Settings > Fields > Custom Fields > Create Field (Paragraph/Text Area)."
                )
            else:
                error_msg = "No analysis data to publish (no abuse cases or security requirements)."
            logger.error(error_msg)
            raise ValueError(error_msg)

        result = await self.update_issue(issue_key, fields_to_update)
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
