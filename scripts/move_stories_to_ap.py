"""
Move user stories from Jira project "Apex" to project "AP" as Story issue type.

Usage:
    python scripts/move_stories_to_ap.py \
        --url https://yoursite.atlassian.net \
        --email your-email@example.com \
        --token YOUR_API_TOKEN

Optional:
    --source-project APEX       Source project key (default: APEX)
    --target-project AP         Target project key (default: AP)
    --dry-run                   Preview without creating issues
"""

import argparse
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from services.jira_client import JiraClient


async def main():
    parser = argparse.ArgumentParser(description="Move Jira stories between projects")
    parser.add_argument("--url", required=True, help="Jira base URL (e.g. https://yoursite.atlassian.net)")
    parser.add_argument("--email", required=True, help="Jira account email")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--source-project", default="APEX", help="Source project key (default: APEX)")
    parser.add_argument("--target-project", default="AP", help="Target project key (default: AP)")
    parser.add_argument("--dry-run", action="store_true", help="Preview only, don't create issues")
    args = parser.parse_args()

    client = JiraClient(base_url=args.url, email=args.email, api_token=args.token)

    # Test connection
    print("Testing Jira connection...")
    result = await client.test_connection()
    if not result["success"]:
        print(f"Connection failed: {result['message']}")
        return
    print(f"Connected: {result['message']}")

    # Fetch stories from source project
    print(f"\nFetching stories from project '{args.source_project}'...")
    try:
        issues = await client.get_project_issues(
            project_id=args.source_project,
            issue_types=["Story", "User Story", "Task"],
            max_results=200,
        )
    except Exception as e:
        print(f"Failed to fetch issues: {e}")
        return

    if not issues:
        print("No stories found in source project.")
        return

    print(f"Found {len(issues)} stories to move.\n")

    created = 0
    failed = 0

    for issue in issues:
        fields = issue.get("fields", {})
        key = issue.get("key", "?")
        summary = fields.get("summary", "No summary")
        description = JiraClient.extract_description_text(fields.get("description"))

        print(f"  [{key}] {summary}")

        if args.dry_run:
            print(f"    -> [DRY RUN] Would create in {args.target_project}")
            created += 1
            continue

        try:
            new_issue = await client.create_issue(
                project_key=args.target_project,
                summary=summary,
                description=description or "No description",
                issue_type="Story",
            )
            new_key = new_issue.get("key", "?")
            print(f"    -> Created {new_key}")
            created += 1
        except Exception as e:
            print(f"    -> FAILED: {e}")
            failed += 1

    print(f"\nDone! Created: {created}, Failed: {failed}")
    if args.dry_run:
        print("(Dry run — no issues were actually created. Remove --dry-run to execute.)")


if __name__ == "__main__":
    asyncio.run(main())
