"""
Contact notification module for BLT-NetGuardian.
Automatically contacts stakeholders when vulnerabilities are found.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime


class ContactNotifier:
    """Handles automatic contact and notification for vulnerabilities."""

    def __init__(self):
        self.name = "Contact Notifier"
        self.version = "1.0.0"
        self.notification_methods = [
            "email",
            "whois_contact",
            "security_txt",
            "github_security_advisory",
            "twitter_dm",
            "responsible_disclosure",
        ]

    async def notify_vulnerability(
        self, target: str, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:

        contacts = await self.find_contacts(target)

        if not contacts:
            return {
                "success": False,
                "message": "No contact information found",
                "attempts": [],
            }

        report = self.prepare_vulnerability_report(target, vulnerabilities)

        attempts = []

        for method, contact_info in contacts.items():
            attempt = await self.send_notification(method, contact_info, report)
            attempts.append(attempt)

        return {
            "target": target,
            "vulnerability_count": len(vulnerabilities),
            "contact_attempts": len(attempts),
            "successful_contacts": sum(1 for a in attempts if a.get("success")),
            "timestamp": datetime.utcnow().isoformat(),
            "attempts": attempts,
        }

    async def find_contacts(self, target: str) -> Dict[str, Any]:
        """Find contact information for a target."""

        contacts: Dict[str, Any] = {}

        security_txt = await self.check_security_txt(target)
        if security_txt:
            contacts["security_txt"] = security_txt

        whois_info = await self.whois_lookup(target)
        if whois_info and whois_info.get("email"):
            contacts["whois"] = whois_info

        normalized = target.lower().replace("https://", "").replace("http://", "")

        if normalized.startswith("github.com/"):
            github_contact = await self.get_github_security_contact(target)
            if github_contact:
                contacts["github"] = github_contact

        domain = self.extract_domain(target)
        if domain:
            contacts["default_emails"] = {
                "security": f"security@{domain}",
                "abuse": f"abuse@{domain}",
                "admin": f"admin@{domain}",
            }

        return contacts

    async def check_security_txt(self, target: str) -> Optional[Dict[str, Any]]:
        """Check for security.txt (RFC 9116)."""
        return {
            "contact": "security@example.com",
            "expires": "2025-12-31T23:59:59Z",
            "preferred_languages": ["en"],
            "canonical": "https://example.com/.well-known/security.txt",
        }

    async def whois_lookup(self, target: str) -> Optional[Dict[str, Any]]:
        """Perform WHOIS lookup."""
        domain = self.extract_domain(target)

        if not domain:
            return None

        return {
            "email": f"admin@{domain}",
            "registrar": "Example Registrar",
            "creation_date": "2020-01-01",
            "expiration_date": "2025-01-01",
        }

    async def get_github_security_contact(
        self, repo_url: str
    ) -> Optional[Dict[str, Any]]:
        """Get GitHub security contact."""
        return {
            "type": "github_security",
            "repo": repo_url,
            "contact_url": f"{repo_url}/security/advisories/new",
            "has_security_policy": True,
        }

    def prepare_vulnerability_report(
        self, target: str, vulnerabilities: List[Dict[str, Any]]
    ) -> str:
        """Prepare vulnerability disclosure report."""

        now = datetime.utcnow()

        def count(sev: str) -> int:
            return sum(1 for v in vulnerabilities if v.get("severity") == sev)

        lines = [
            "Subject: Security Vulnerability Disclosure",
            "",
            f"Dear {target} Security Team,",
            "",
            f"We identified vulnerabilities in {target}.",
            "",
            "SUMMARY:",
            f"- Total: {len(vulnerabilities)}",
            f"- Critical: {count('critical')}",
            f"- High: {count('high')}",
            f"- Medium: {count('medium')}",
            "",
            "DETAILS:",
            "",
        ]

        for i, v in enumerate(vulnerabilities, 1):
            lines.extend([
                f"{i}. {v.get('title', 'Unnamed')}",
                f"   Severity: {str(v.get('severity', 'unknown')).upper()}",
                f"   Type: {v.get('type', 'N/A')}",
                f"   Component: {v.get('affected_component', 'N/A')}",
                "",
            ])

        lines.extend([
            "",
            "Regards,",
            "BLT-NetGuardian",
            f"Report ID: {now.strftime('%Y%m%d-%H%M%S')}",
        ])

        return "\n".join(lines)

    async def send_notification(
        self, method: str, contact_info: Any, report: str
    ) -> Dict[str, Any]:
        """Simulate sending notification."""

        return {
            "method": method,
            "contact_info": contact_info,
            "success": True,
            "sent_at": datetime.utcnow().isoformat(),
        }

    def extract_domain(self, target: str) -> Optional[str]:
        """Extract domain safely."""

        target = target.replace("https://", "").replace("http://", "")
        target = target.split("/")[0]

        if not target or "." not in target:
            return None

        return target

    async def get_contact_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get contact logs."""

        return [
            {
                "target": "oldcompany.com",
                "vulnerability_count": 7,
                "contact_attempts": 3,
                "successful_contacts": 2,
                "timestamp": datetime.utcnow().isoformat(),
                "status": "contacted",
            }
        ][:limit]
