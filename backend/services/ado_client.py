"""Azure DevOps REST API client for syncing work items and pushing security analysis."""

import logging
import re
from base64 import b64encode
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class ADOClient:
    def __init__(self, org_url: str, pat: str, project: Optional[str] = None):
        self.org_url = org_url.rstrip("/")
        self.project = project
        auth = b64encode(f":{pat}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json-patch+json",
        }
        self.json_headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict:
        """Test the ADO connection."""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{self.org_url}/_apis/projects?api-version=7.1",
                    headers=self.json_headers
                )
                if resp.status_code == 200:
                    data = resp.json()
                    count = data.get("count", 0)
                    return {"success": True, "message": f"Connected. Found {count} projects."}
                return {"success": False, "message": f"Authentication failed: {resp.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    async def get_projects(self) -> list[dict]:
        """Get all accessible ADO projects."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.org_url}/_apis/projects?api-version=7.1",
                headers=self.json_headers
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("value", [])

    async def get_work_items(
        self,
        project: str,
        work_item_types: list[str] = None,
        max_results: int = 100
    ) -> list[dict]:
        """Get work items (user stories) from an ADO project."""
        if not work_item_types:
            work_item_types = ["User Story", "Product Backlog Item", "Feature"]

        # Build WIQL query
        types_clause = " OR ".join(f"[System.WorkItemType] = '{t}'" for t in work_item_types)
        wiql = f"""
        SELECT [System.Id], [System.Title], [System.Description], [System.WorkItemType], [System.State]
        FROM WorkItems
        WHERE [System.TeamProject] = '{project}'
        AND ({types_clause})
        ORDER BY [System.CreatedDate] DESC
        """

        async with httpx.AsyncClient(timeout=60) as client:
            # Execute WIQL query
            resp = await client.post(
                f"{self.org_url}/{project}/_apis/wit/wiql?api-version=7.1&$top={max_results}",
                json={"query": wiql},
                headers=self.json_headers
            )
            resp.raise_for_status()
            query_result = resp.json()

            work_item_ids = [wi["id"] for wi in query_result.get("workItems", [])]
            if not work_item_ids:
                return []

            # Fetch work item details in batches
            batch_size = 200
            all_items = []
            for i in range(0, len(work_item_ids), batch_size):
                batch_ids = work_item_ids[i:i + batch_size]
                ids_str = ",".join(str(id) for id in batch_ids)
                resp = await client.get(
                    f"{self.org_url}/_apis/wit/workitems?ids={ids_str}&api-version=7.1&$expand=all",
                    headers=self.json_headers
                )
                resp.raise_for_status()
                batch_data = resp.json()
                all_items.extend(batch_data.get("value", []))

            return all_items

    async def get_work_item(self, work_item_id: int) -> dict:
        """Get work item details."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.org_url}/_apis/wit/workitems/{work_item_id}?api-version=7.1&$expand=all",
                headers=self.json_headers
            )
            resp.raise_for_status()
            return resp.json()

    async def update_work_item(self, work_item_id: int, operations: list[dict]) -> dict:
        """Update work item fields using JSON Patch operations."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.patch(
                f"{self.org_url}/_apis/wit/workitems/{work_item_id}?api-version=7.1",
                json=operations,
                headers=self.headers
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info("Updated ADO work item: %s", work_item_id)
            return data

    def _build_abuse_cases_html(self, abuse_cases: list[dict]) -> str:
        """Build HTML content for abuse cases."""
        html = [
            '<div style="border: 2px solid #f59e0b; border-radius: 8px; padding: 16px; margin-top: 16px; background: #fffbeb;">',
            '<h3 style="color: #f59e0b; margin-top: 0;">⚠️ Abuse Cases</h3>',
        ]

        for i, ac in enumerate(abuse_cases, 1):
            impact_color = "#ef4444" if ac.get("impact") == "Critical" else "#f59e0b" if ac.get("impact") == "High" else "#eab308"
            html.append(f'''
            <div style="border: 1px solid #fcd34d; border-radius: 4px; padding: 12px; margin-bottom: 12px; background: white;">
                <h4 style="margin: 0 0 8px 0; color: #92400e;">#{i}: {ac.get("threat", "Unknown")}</h4>
                <table style="width: 100%; font-size: 0.9em;">
                    <tr><td style="width: 120px;"><strong>Threat Actor:</strong></td><td>{ac.get("actor", "N/A")}</td></tr>
                    <tr><td><strong>Impact:</strong></td><td style="color: {impact_color}; font-weight: bold;">{ac.get("impact", "N/A")}</td></tr>
                    <tr><td><strong>Likelihood:</strong></td><td>{ac.get("likelihood", "N/A")}</td></tr>
                    <tr><td><strong>Attack Vector:</strong></td><td>{ac.get("attack_vector", "N/A")}</td></tr>
                </table>
            </div>
            ''')

        html.append(f'<p style="color: #78716c; font-size: 0.85em; margin-bottom: 0;"><em>Generated by SecureDev AI | Total: {len(abuse_cases)} abuse cases</em></p>')
        html.append('</div>')
        return ''.join(html)

    def _build_security_requirements_html(self, requirements: list[dict]) -> str:
        """Build HTML content for security requirements."""
        html = [
            '<div style="border: 2px solid #6366f1; border-radius: 8px; padding: 16px; margin-top: 16px; background: #eef2ff;">',
            '<h3 style="color: #6366f1; margin-top: 0;">🛡️ Security Requirements</h3>',
            '<table style="width: 100%; border-collapse: collapse; font-size: 0.9em; background: white;">',
            '<tr style="background: #e0e7ff;"><th style="border: 1px solid #c7d2fe; padding: 8px;">ID</th><th style="border: 1px solid #c7d2fe; padding: 8px;">Priority</th><th style="border: 1px solid #c7d2fe; padding: 8px;">Category</th><th style="border: 1px solid #c7d2fe; padding: 8px; text-align: left;">Requirement</th></tr>',
        ]

        for req in requirements:
            priority_color = "#ef4444" if req.get("priority") == "Critical" else "#f59e0b" if req.get("priority") == "High" else "#3b82f6"
            html.append(f'''
            <tr>
                <td style="border: 1px solid #c7d2fe; padding: 8px; font-family: monospace;">{req.get("id", "N/A")}</td>
                <td style="border: 1px solid #c7d2fe; padding: 8px; text-align: center; color: {priority_color}; font-weight: bold;">{req.get("priority", "N/A")}</td>
                <td style="border: 1px solid #c7d2fe; padding: 8px; text-align: center;">{req.get("category", "N/A")}</td>
                <td style="border: 1px solid #c7d2fe; padding: 8px;">{req.get("text", "")}</td>
            </tr>
            ''')

        html.append('</table>')
        html.append(f'<p style="color: #78716c; font-size: 0.85em; margin-bottom: 0; margin-top: 12px;"><em>Generated by SecureDev AI | Total: {len(requirements)} requirements</em></p>')
        html.append('</div>')
        return ''.join(html)

    async def publish_analysis_to_work_item(
        self,
        work_item_id: int,
        analysis: dict,
        abuse_cases_field: Optional[str] = None,
        security_req_field: Optional[str] = None
    ) -> dict:
        """
        Publish analysis results to ADO work item custom fields.
        Falls back to appending to description if custom fields not configured.
        """
        abuse_cases = analysis.get("abuse_cases", [])
        requirements = analysis.get("security_requirements", [])
        risk_score = analysis.get("risk_score", 0)

        operations = []
        updated_fields = []

        # Use custom fields if provided
        if abuse_cases_field and abuse_cases:
            abuse_html = self._build_abuse_cases_html(abuse_cases)
            operations.append({"op": "add", "path": f"/fields/{abuse_cases_field}", "value": abuse_html})
            updated_fields.append(abuse_cases_field)

        if security_req_field and requirements:
            req_html = self._build_security_requirements_html(requirements)
            operations.append({"op": "add", "path": f"/fields/{security_req_field}", "value": req_html})
            updated_fields.append(security_req_field)

        # Always update description with analysis summary
        work_item = await self.get_work_item(work_item_id)
        current_desc = work_item.get("fields", {}).get("System.Description", "") or ""

        # Remove existing analysis section
        pattern = r'<div style="border: 2px solid #6366f1;.*?Generated by SecureDev AI.*?</div>\s*'
        current_desc = re.sub(pattern, '', current_desc, flags=re.DOTALL)
        pattern2 = r'<div style="border: 2px solid #f59e0b;.*?Generated by SecureDev AI.*?</div>\s*'
        current_desc = re.sub(pattern2, '', current_desc, flags=re.DOTALL)

        # Build new analysis HTML if no custom fields
        if not abuse_cases_field or not security_req_field:
            analysis_parts = []
            if abuse_cases and not abuse_cases_field:
                analysis_parts.append(self._build_abuse_cases_html(abuse_cases))
            if requirements and not security_req_field:
                analysis_parts.append(self._build_security_requirements_html(requirements))

            if analysis_parts:
                new_desc = current_desc.strip() + "\n\n" + "\n".join(analysis_parts)
                operations.append({"op": "replace", "path": "/fields/System.Description", "value": new_desc})
                updated_fields.append("System.Description")

        if not operations:
            raise ValueError("No analysis data to publish.")

        result = await self.update_work_item(work_item_id, operations)
        logger.info("Updated ADO work item %s with fields: %s", work_item_id, updated_fields)

        return result

    @staticmethod
    def extract_description_text(description: str | None) -> str:
        """Extract plain text from HTML description."""
        if not description:
            return ""
        # Simple HTML tag removal
        text = re.sub(r'<[^>]+>', ' ', description)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
