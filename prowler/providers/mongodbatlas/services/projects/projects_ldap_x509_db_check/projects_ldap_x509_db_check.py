from typing import List

from prowler.lib.check.models import Check, CheckReportMongoDBAtlas
from prowler.providers.mongodbatlas.services.projects.projects_client import (
    projects_client,
)


class projects_ldap_x509_db_check(Check):
    """Check if MongoDB Atlas project have LDAP configured.

    This class verifies that MongoDB Atlas projects have LDAP configured for database user management.
    """

    def execute(self) -> List[CheckReportMongoDBAtlas]:
        """Execute the MongoDB Atlas project have LDAP configured check

        check if have LDAP configuration is enabled.

        Returns:
            List[CheckReportMongoDBAtlas]: A list of reports for each project
        """
        findings = []

        for project in projects_client.projects.values():
            report = CheckReportMongoDBAtlas(metadata=self.metadata(), resource=project)
            ldap_auth_type = project.database_users_config.get("ldapAuthType", "NONE")
            if ldap_auth_type == "NONE" :
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} has no ldap configuration enabled."
                )
            else :
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} have LDAP configured with {ldap_auth_type}"
                )

            findings.append(report)

        return findings
