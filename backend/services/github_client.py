"""
GitHub REST API Client for Commit Monitoring
"""
import httpx
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"


class GitHubClient:
    """Async GitHub REST API client using PAT authentication."""

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def _get(self, path: str, params: Optional[Dict] = None) -> Any:
        url = f"{GITHUB_API_BASE}{path}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()

    async def get_repos(self, org: str) -> List[Dict]:
        """List repositories for an organization."""
        results = []
        page = 1
        while True:
            data = await self._get(f"/orgs/{org}/repos", params={"per_page": 100, "page": page, "type": "all"})
            if not data:
                break
            results.extend(data)
            if len(data) < 100:
                break
            page += 1
        return results

    async def get_repo(self, owner: str, repo: str) -> Dict:
        """Get repository metadata."""
        return await self._get(f"/repos/{owner}/{repo}")

    async def get_recent_commits(self, owner: str, repo: str, since_hours: int = 24, branch: str = "main") -> List[Dict]:
        """Fetch commits since N hours ago on the given branch."""
        since_dt = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            commits = await self._get(
                f"/repos/{owner}/{repo}/commits",
                params={"sha": branch, "since": since_iso, "per_page": 100}
            )
            return commits if isinstance(commits, list) else []
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 409:
                # Empty repo
                return []
            raise

    async def get_commit_detail(self, owner: str, repo: str, sha: str) -> Dict:
        """Get full commit details including file changes and stats."""
        return await self._get(f"/repos/{owner}/{repo}/commits/{sha}")

    async def get_commit_diff(self, owner: str, repo: str, sha: str) -> str:
        """Get raw unified diff for a commit."""
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/commits/{sha}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                url,
                headers={**self.headers, "Accept": "application/vnd.github.v3.diff"},
            )
            response.raise_for_status()
            return response.text

    async def test_connection(self) -> Dict:
        """Test PAT validity by fetching authenticated user info."""
        return await self._get("/user")
