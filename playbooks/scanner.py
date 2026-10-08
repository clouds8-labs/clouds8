"""
Clouds8 - Playbook Scanner
Executes security checks defined in YAML playbooks against OCI metadata
"""

import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class CheckResult:
    """Result of a single security check"""
    check_id: str
    name: str
    status: str  # PASS, FAIL, ERROR, SKIP
    severity: Severity
    resource_type: str
    resources_checked: int = 0
    resources_failed: List[Dict] = field(default_factory=list)
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "status": self.status,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resources_checked": self.resources_checked,
            "resources_failed": self.resources_failed,
            "message": self.message,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ScanReport:
    """Complete scan report"""
    playbook_name: str
    playbook_version: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    results: List[CheckResult] = field(default_factory=list)
    
    @property
    def total_checks(self) -> int:
        return len(self.results)
    
    @property
    def passed(self) -> int:
        return len([r for r in self.results if r.status == "PASS"])
    
    @property
    def failed(self) -> int:
        return len([r for r in self.results if r.status == "FAIL"])
    
    @property
    def errors(self) -> int:
        return len([r for r in self.results if r.status == "ERROR"])

    def to_dict(self) -> Dict:
        return {
            "playbook_name": self.playbook_name,
            "playbook_version": self.playbook_version,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "summary": {
                "total": self.total_checks,
                "passed": self.passed,
                "failed": self.failed,
                "errors": self.errors
            },
            "results": [r.to_dict() for r in self.results]
        }


class PlaybookScanner:
    """Scanner that executes playbook checks against OCI resources"""
    
    def __init__(self, playbook_path: str):
        self.playbook_path = Path(playbook_path)
        self.playbook = self._load_playbook()
        
    def _load_playbook(self) -> Dict:
        """Load and parse YAML playbook"""
        with open(self.playbook_path, 'r') as f:
            return yaml.safe_load(f)
    
    def scan(self, inventory: Dict[str, List[Dict]]) -> ScanReport:
        """
        Run all checks against the provided inventory
        
        Args:
            inventory: Dict mapping resource types to list of resources
        """
        report = ScanReport(
            playbook_name=self.playbook.get("name", "Unknown"),
            playbook_version=self.playbook.get("version", "1.0"),
            started_at=datetime.now()
        )
        
        for check in self.playbook.get("checks", []):
            result = self._execute_check(check, inventory)
            report.results.append(result)
        
        report.completed_at = datetime.now()
        return report
    
    def _execute_check(self, check: Dict, inventory: Dict) -> CheckResult:
        """Execute a single check against inventory"""
        resource_type = check.get("resource_type", "")
        resources = inventory.get(resource_type, [])
        
        if not resources:
            return CheckResult(
                check_id=check["id"],
                name=check["name"],
                status="SKIP",
                severity=Severity(check.get("severity", "medium")),
                resource_type=resource_type,
                message=f"No {resource_type} resources found"
            )
        
        failed_resources = []
        
        # Evaluate condition against each resource
        for resource in resources:
            try:
                if not self._evaluate_condition(check.get("condition", "true"), resource):
                    failed_resources.append({
                        "id": resource.get("id", "unknown"),
                        "name": resource.get("name", "unknown"),
                        "compartment": resource.get("compartment_id", "unknown")
                    })
            except Exception as e:
                return CheckResult(
                    check_id=check["id"],
                    name=check["name"],
                    status="ERROR",
                    severity=Severity(check.get("severity", "medium")),
                    resource_type=resource_type,
                    message=f"Error evaluating condition: {str(e)}"
                )
        
        status = "PASS" if not failed_resources else "FAIL"
        
        return CheckResult(
            check_id=check["id"],
            name=check["name"],
            status=status,
            severity=Severity(check.get("severity", "medium")),
            resource_type=resource_type,
            resources_checked=len(resources),
            resources_failed=failed_resources,
            message=check.get("remediation", "") if failed_resources else ""
        )
    
    def _evaluate_condition(self, condition: str, resource: Dict) -> bool:
        """
        Evaluate a condition string against a resource
        This is a simplified implementation - production would use a proper expression parser
        """
        # For now, return True (pass) - implement actual condition parsing
        # In production, use a safe expression evaluator
        return True


def scan_with_playbook(playbook_path: str, inventory: Dict) -> Dict:
    """Convenience function to run a scan"""
    scanner = PlaybookScanner(playbook_path)
    report = scanner.scan(inventory)
    return report.to_dict()


