from typing import Dict

from certipy.commands.find import filetime_to_str
from certipy.lib.constants import (
    CertificateNameFlag,
    EnrollmentFlag,
    PrivateKeyFlag,
    OID_TO_STR_MAP,
)
from certipy.lib.ldap import LDAPEntry


class MockLDAPEntry(LDAPEntry):
    def __init__(self, attributes):
        self.attributes = attributes

    def __getitem__(self, key):
        return self.__dict__[key]


class CertTemplate:
    def __init__(self, name: str, data: Dict):
        self.data = data

        self.name = name
        self.display_name = self.data["DisplayName"]
        self.schema_version = self.data["msPKI-Template-Schema-Version"]
        if self.schema_version:
            self.schema_version = int(self.schema_version)
        else:
            self.schema_version = 1
        self.oid = self.data["msPKI-Cert-Template-OID"]
        self.validity_period = filetime_to_str(self.data["ValidityPeriod"])
        self.renewal_period = filetime_to_str(self.data["RenewalOverlap"])
        self.name_flags = CertificateNameFlag(self.data["msPKI-Certificate-Name-Flag"])

        self.enrollment_flags = EnrollmentFlag(self.data["msPKI-Enrollment-Flag"])
        self.private_key_flag = PrivateKeyFlag(self.data["msPKI-Private-Key-Flag"])
        self.signatures_required = self.data["msPKI-RA-Signature"]

        self.extended_key_usage = list(
            map(
                lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x,
                data["ExtKeyUsageSyntax"],
            )
        )
        self.application_policies = list(
            map(
                lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x,
                data["msPKI-RA-Application-Policies"],
            )
        )
        self.issuance_policies = list(
            map(
                lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x,
                data["msPKI-Certificate-Policy"],
            )
        )

    @property
    def any_purpose(self):
        return "Any Purpose" in self.extended_key_usage

    def to_dict(self):
        return MockLDAPEntry(
            {
                "cn": self.name,
                "displayName": self.display_name,
                "Template OID": self.oid,
                "validity_period": self.validity_period,
                "renewal_period": self.renewal_period,
                "certificate_name_flag": self.name_flags,
                "enrollment_flag": self.enrollment_flags,
                "authorized_signatures_required": self.signatures_required,
                "extended_key_usage": self.extended_key_usage,
                "nTSecurityDescriptor": self.data["Security"],
                "enrollee_supplies_subject": CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT
                in self.name_flags,
                "enrollment_agent": "Certificate Request Agent"
                in self.extended_key_usage,
                "any_purpose": self.any_purpose,
                "client_authentication": self.any_purpose
                or any(
                    eku in self.extended_key_usage
                    for eku in [
                        "Client Authentication",
                        "Smart Card Logon",
                        "PKINIT Client Authentication",
                    ]
                ),
                "private_key_flag": self.private_key_flag,
                "requires_manager_approval": EnrollmentFlag.PEND_ALL_REQUESTS
                in self.enrollment_flags,
                "requires_key_archival": PrivateKeyFlag.REQUIRE_PRIVATE_KEY_ARCHIVAL
                in self.private_key_flag,
                "application_policies": self.application_policies,
                "schema_version": self.schema_version,
                "msPKI-Minimal-Key-Size": self.data["msPKI-Minimal-Key-Size"],
                "msPKI-Certificate-Policy": self.issuance_policies,
                "enabled": True,
            }
        )
