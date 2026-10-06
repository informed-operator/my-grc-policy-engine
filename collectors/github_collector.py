#!/usr/bin/env python3
"""
ISO 27001 A.8.28 GitHub Telemetry Collector
Queries the GitHub REST API to extract security configurations and vulnerability metrics,
then normalizes the output into an OPA/Rego-compatible input JSON.
"""

import json
import os
import sys
import requests

GITHUB_API_URL = "https://api.github.com"


class GitHubCollector:

    def __init__(self, token: str):
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def _get(self, endpoint: str):
        url = f"{GITHUB_API_URL}{endpoint}"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        return None

    def get_repo_data(self, owner: str, repo: str) -> dict | None:
        full_name = f"{owner}/{repo}"
        print(f"[*] Collecting telemetry for: {full_name}")

        repo_info = self._get(f"/repos/{full_name}")
        if not repo_info:
            print(
                f"[!] Error: Unable to fetch repo {full_name}. Check token permissions or repo existence."
            )
            return None

        default_branch = repo_info.get("default_branch", "main")

        # 1. Check Secure Coding Standard (e.g., SECURITY.md or CODING_STANDARDS.md)
        security_doc = self._get(f"/repos/{full_name}/contents/SECURITY.md")
        has_secure_standard = security_doc is not None

        # 2. Check Branch Protection Rules on Default Branch
        protection_info = self._get(
            f"/repos/{full_name}/branches/{default_branch}/protection"
        )
        default_branch_protected = protection_info is not None
        code_review_required = False

        if default_branch_protected and "required_pull_request_reviews" in protection_info:
            code_review_required = True

        # 3. Check for SAST Workflow Configuration (.github/workflows)
        workflows = self._get(f"/repos/{full_name}/contents/.github/workflows")
        sast_enabled = False
        if workflows and isinstance(workflows, list):
            sast_files = [
                f["name"]
                for f in workflows
                if "codeql" in f["name"].lower() or "sast" in f["name"].lower()
            ]
            sast_enabled = len(sast_files) > 0

        # 4. Check Security Features (Secret Scanning & Dependabot)
        sec_analysis = repo_info.get("security_and_analysis", {})
        secret_scan_enabled = (
            sec_analysis.get("secret_scanning", {}).get("status") == "enabled"
        )
        dependabot_enabled = (
            sec_analysis.get("dependabot_security_updates", {}).get("status")
            == "enabled"
        )

        # 5. Check Active Security Findings via API
        secret_alerts = self._get(
            f"/repos/{full_name}/secret-scanning/alerts?state=open"
        )
        secrets_in_repo = (
            isinstance(secret_alerts, list) and len(secret_alerts) > 0
        )

        sast_alerts = self._get(
            f"/repos/{full_name}/code-scanning/alerts?state=open&severity=critical"
        )
        critical_sast_open = (
            isinstance(sast_alerts, list) and len(sast_alerts) > 0
        )

        dependabot_alerts = self._get(
            f"/repos/{full_name}/dependabot/alerts?state=open&severity=critical"
        )
        critical_cves_unfixed = (
            isinstance(dependabot_alerts, list) and len(dependabot_alerts) > 0
        )

        return {
            "id": repo,
            "in_scope": True,
            "secure_coding_standard_applied": has_secure_standard,
            "default_branch_protected": default_branch_protected,
            "code_review_required": code_review_required,
            "sast_enabled": sast_enabled,
            "secret_scan_enabled": secret_scan_enabled,
            "dependency_scan_enabled": dependabot_enabled,
            "secrets_in_repo": secrets_in_repo,
            "critical_sast_open": critical_sast_open,
            "critical_cves_unfixed": critical_cves_unfixed,
        }


def main():
    token = os.getenv("GITHUB_TOKEN")
    target_repos_env = os.getenv("TARGET_REPOS")

    if not token:
        print(
            "[!] Error: GITHUB_TOKEN environment variable not set."
        )
        sys.exit(1)

    if not target_repos_env:
        print(
            "[!] Error: TARGET_REPOS environment variable not set. (Format: 'owner/repo1,owner/repo2')"
        )
        sys.exit(1)

    repo_list = [r.strip() for r in target_repos_env.split(",") if r.strip()]
    collector = GitHubCollector(token=token)

    collected_repos = []
    for full_repo in repo_list:
        parts = full_repo.split("/")
        if len(parts) != 2:
            print(f"[!] Invalid repo format '{full_repo}'. Use 'owner/repo'.")
            continue
        data = collector.get_repo_data(parts[0], parts[1])
        if data:
            collected_repos.append(data)

    if len(collected_repos) == 0:
        print("[!] No valid repositories collected. Exiting.")
        sys.exit(1)
    
    output = {"repositories": collected_repos}

    output_path = "input.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[+] Successfully exported telemetry to {output_path}")


if __name__ == "__main__":
    main()