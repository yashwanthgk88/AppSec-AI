"""ServiceNow REST API client for syncing requests/stories and pushing security analysis."""

import logging
from base64 import b64encode
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class SNOWClient:
    def __init__(self, instance_url: str, username: str, password: str):
        self.instance_url = instance_url.rstrip("/")
        auth = b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict:
        """Test the ServiceNow connection."""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{self.instance_url}/api/now/table/sys_user?sysparm_limit=1",
                    headers=self.headers
                )
                if resp.status_code == 200:
                    return {"success": True, "message": "Connected to ServiceNow instance"}
                elif resp.status_code == 401:
                    return {"success": False, "message": "Authentication failed. Check username/password."}
                return {"success": False, "message": f"Connection failed: {resp.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    async def get_stories(
        self,
        table: str = "rm_story",
        assignment_group: Optional[str] = None,
        product: Optional[str] = None,
        max_results: int = 100
    ) -> list[dict]:
        """
        Get user stories from ServiceNow.

        Args:
            table: The table to query (rm_story for Agile, sc_req_item for catalog requests)
            assignment_group: Filter by assignment group sys_id
            product: Filter by product sys_id
            max_results: Maximum number of results to return
        """
        query_parts = []
        if assignment_group:
            query_parts.append(f"assignment_group={assignment_group}")
        if product:
            query_parts.append(f"product={product}")

        params = {
            "sysparm_limit": max_results,
            "sysparm_display_value": "true",
            "sysparm_exclude_reference_link": "true",
        }
        if query_parts:
            params["sysparm_query"] = "^".join(query_parts) + "^ORDERBYDESCsys_created_on"
        else:
            params["sysparm_query"] = "ORDERBYDESCsys_created_on"

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(
                f"{self.instance_url}/api/now/table/{table}",
                headers=self.headers,
                params=params
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("result", [])

    async def get_record(self, table: str, sys_id: str) -> dict:
        """Get a single record by sys_id."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.instance_url}/api/now/table/{table}/{sys_id}",
                headers=self.headers,
                params={"sysparm_display_value": "true"}
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("result", {})

    async def update_record(self, table: str, sys_id: str, fields: dict) -> dict:
        """Update a record's fields."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.patch(
                f"{self.instance_url}/api/now/table/{table}/{sys_id}",
                json=fields,
                headers=self.headers
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info("Updated SNOW record %s/%s", table, sys_id)
            return data.get("result", {})

    async def get_assignment_groups(self) -> list[dict]:
        """Get all assignment groups."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.instance_url}/api/now/table/sys_user_group",
                headers=self.headers,
                params={
                    "sysparm_limit": 500,
                    "sysparm_fields": "sys_id,name",
                    "sysparm_query": "active=true^ORDERBYname"
                }
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("result", [])

    async def get_products(self) -> list[dict]:
        """Get all products (for Agile Development)."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.instance_url}/api/now/table/rm_product",
                headers=self.headers,
                params={
                    "sysparm_limit": 500,
                    "sysparm_fields": "sys_id,name,short_description",
                    "sysparm_query": "active=true^ORDERBYname"
                }
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("result", [])

    def _format_abuse_cases_text(self, abuse_cases: list[dict]) -> str:
        """Format abuse cases as plain text (SNOW fields are often plain text)."""
        lines = ["=" * 50, "ABUSE CASES - Security Analysis", "=" * 50, ""]

        for i, ac in enumerate(abuse_cases, 1):
            lines.append(f"--- Abuse Case #{i} ---")
            lines.append(f"Threat: {ac.get('threat', 'N/A')}")
            lines.append(f"Threat Actor: {ac.get('actor', 'N/A')}")
            lines.append(f"Impact: {ac.get('impact', 'N/A')}")
            lines.append(f"Likelihood: {ac.get('likelihood', 'N/A')}")
            lines.append(f"Attack Vector: {ac.get('attack_vector', 'N/A')}")
            if ac.get("mitigations"):
                lines.append("Mitigations:")
                for m in ac.get("mitigations", []):
                    lines.append(f"  - {m}")
            lines.append("")

        lines.append("=" * 50)
        lines.append(f"Generated by SecureDev AI | Total: {len(abuse_cases)} abuse cases")
        lines.append("=" * 50)

        return "\n".join(lines)

    def _format_security_requirements_text(self, requirements: list[dict]) -> str:
        """Format security requirements as plain text."""
        lines = ["=" * 50, "SECURITY REQUIREMENTS", "=" * 50, ""]

        # Group by priority
        priority_order = ["Critical", "High", "Medium", "Low"]
        grouped = {p: [] for p in priority_order}
        for req in requirements:
            priority = req.get("priority", "Medium")
            if priority in grouped:
                grouped[priority].append(req)
            else:
                grouped["Medium"].append(req)

        for priority in priority_order:
            reqs = grouped[priority]
            if not reqs:
                continue

            lines.append(f"--- {priority.upper()} PRIORITY ({len(reqs)}) ---")
            for req in reqs:
                lines.append(f"[{req.get('id', 'N/A')}] {req.get('text', '')}")
                lines.append(f"    Category: {req.get('category', 'N/A')}")
                if req.get("details"):
                    lines.append(f"    Details: {req.get('details')}")
                lines.append("")

        lines.append("=" * 50)
        lines.append(f"Generated by SecureDev AI | Total: {len(requirements)} requirements")
        lines.append("=" * 50)

        return "\n".join(lines)

    async def publish_analysis_to_record(
        self,
        table: str,
        sys_id: str,
        analysis: dict,
        abuse_cases_field: Optional[str] = None,
        security_req_field: Optional[str] = None
    ) -> dict:
        """
        Publish analysis results to ServiceNow record custom fields.

        Args:
            table: The table containing the record (e.g., rm_story)
            sys_id: The sys_id of the record to update
            analysis: The security analysis results
            abuse_cases_field: Custom field name for abuse cases (e.g., u_abuse_cases)
            security_req_field: Custom field name for security requirements (e.g., u_security_requirements)
        """
        abuse_cases = analysis.get("abuse_cases", [])
        requirements = analysis.get("security_requirements", [])
        risk_score = analysis.get("risk_score", 0)

        fields_to_update = {}

        if abuse_cases_field and abuse_cases:
            fields_to_update[abuse_cases_field] = self._format_abuse_cases_text(abuse_cases)

        if security_req_field and requirements:
            fields_to_update[security_req_field] = self._format_security_requirements_text(requirements)

        # Add risk score if there's a field for it
        # fields_to_update["u_risk_score"] = str(risk_score)

        if not fields_to_update:
            # Fallback: append to work notes
            work_notes = []
            if abuse_cases:
                work_notes.append(self._format_abuse_cases_text(abuse_cases))
            if requirements:
                work_notes.append(self._format_security_requirements_text(requirements))

            if work_notes:
                fields_to_update["work_notes"] = "\n\n".join(work_notes)
            else:
                raise ValueError("No analysis data to publish.")

        result = await self.update_record(table, sys_id, fields_to_update)
        logger.info("Published analysis to SNOW %s/%s", table, sys_id)

        return result

    @staticmethod
    def extract_description_text(record: dict, field: str = "short_description") -> str:
        """Extract description text from a SNOW record."""
        return record.get(field, "") or record.get("description", "") or ""
