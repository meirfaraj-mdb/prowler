from typing import List

from prowler.lib.check.models import Check, CheckReportMongoDBAtlas
from prowler.providers.mongodbatlas.services.projects.projects_client import (
    projects_client,
)


class projects_audit_log_enabled(Check):
    """Check if MongoDB Atlas project Auditing enabled.
    """

    def execute(self) -> List[CheckReportMongoDBAtlas]:
        """Execute the MongoDB Atlas project auditing enabled check

        Iterates over all projects and checks if they have auditing enabled.

        Returns:
            List[CheckReportMongoDBAtlas]: A list of reports for each project
        """
        findings = []

        for project in projects_client.projects.values():
            report = CheckReportMongoDBAtlas(metadata=self.metadata(), resource=project)

            if not project.audit_config.get("enabled"):
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} has no auditing configured."
                )
            else:
                # maybe also check that there is an Audit Filter configured to avoid auditing everything
                # or even get from config organization rules for filter
                report.status = "PASS"
                report.status_extended = (
                   f"Project {project.name} has auditing enabled"
                   f"with audit filter {project.audit_config.get("auditFilter")}."
                )

            findings.append(report)

        return findings
