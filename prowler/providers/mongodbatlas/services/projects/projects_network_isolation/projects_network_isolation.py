from typing import List

from prowler.lib.check.models import Check, CheckReportMongoDBAtlas
from prowler.providers.mongodbatlas.services.projects.projects_client import (
    projects_client,
)


class projects_network_isolation(Check):
    """Check if MongoDB Atlas project network peering or private endpoints are
       configured to isolate database from internet.

    This class verifies that MongoDB Atlas projects have network peering or private endpoints
       configured to isolate database from internet.
    """

    def execute(self) -> List[CheckReportMongoDBAtlas]:
        """Execute the MongoDB Atlas project network isolation check

        check if the count of network isolation configuration (peering + private endpoint) is greater than 0.

        Returns:
            List[CheckReportMongoDBAtlas]: A list of reports for each project
        """
        findings = []

        for project in projects_client.projects.values():
            report = CheckReportMongoDBAtlas(metadata=self.metadata(), resource=project)

            if project.network_isolation_count > 0 :
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has {project.network_isolation_count} network isolation configuration (Peering or Private Endpoints) entries configured, "
                )
            else :
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} has no isolation configuration (Peering or Private Endpoints) entries configured, "
                    f" which may expose database to the internet."
                )

            findings.append(report)

        return findings
