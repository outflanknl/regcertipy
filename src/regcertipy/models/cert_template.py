from typing import Dict

import regcertipy.utils
from certipy.commands.find import filetime_to_str
from certipy.lib.constants import (
    CertificateRights,
    EXTENDED_RIGHTS_NAME_MAP,
    CertificateNameFlag,
    EnrollmentFlag,
    PrivateKeyFlag,
    OID_TO_STR_MAP,
)
from certipy.lib.security import CertificateSecurity
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
        self.oid = (
            self.data["msPKI-Cert-Template-OID"].decode("utf-16-le").rstrip("\0\0")
        )
        self.validity_period = filetime_to_str(self.data["ValidityPeriod"])
        self.renewal_period = filetime_to_str(self.data["RenewalOverlap"])
        self.name_flags = CertificateNameFlag(self.data["msPKI-Certificate-Name-Flag"])

        self.enrollment_flags = EnrollmentFlag(self.data["msPKI-Enrollment-Flag"])
        self.private_key_flag = PrivateKeyFlag(self.data["msPKI-Private-Key-Flag"])
        self.signatures_required = self.data["msPKI-RA-Signature"]

        self.extended_key_usage = list(
            map(
                lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x,
                data["ExtKeyUsageSyntax"]
                .decode("utf-16-le")
                .rstrip("\0\0")
                .split("\0"),
            )
        )
        self.application_policies = list(
            map(
                lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x,
                data["msPKI-RA-Application-Policies"]
                .decode("utf-16-le")
                .rstrip("\0\0")
                .split("\0"),
            )
        )
        self.issuance_policies = list(
            map(
                lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x,
                data["msPKI-Certificate-Policy"]
                .decode("utf-16-le")
                .rstrip("\0\0")
                .split("\0"),
            )
        )

        self.permissions = self._build_permissions(self.data["Security"])

    @staticmethod
    def _build_permissions(security_dict: Dict):
        security = CertificateSecurity(security_dict)

        enrollment_permissions = {}
        enrollment_rights = []
        all_extended_rights = []

        permissions = {}

        for sid, rights in security.aces.items():
            if (
                EXTENDED_RIGHTS_NAME_MAP["Enroll"] in rights["extended_rights"]
                or EXTENDED_RIGHTS_NAME_MAP["AutoEnroll"] in rights["extended_rights"]
            ):
                enrollment_rights.append(regcertipy.utils.sid_to_name(sid))
            if (
                EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"]
                in rights["extended_rights"]
            ):
                all_extended_rights.append(regcertipy.utils.sid_to_name(sid))

        if len(enrollment_rights) > 0:
            enrollment_permissions["Enrollment Rights"] = enrollment_rights

        if len(all_extended_rights) > 0:
            enrollment_permissions["All Extended Rights"] = all_extended_rights

        if len(enrollment_permissions) > 0:
            permissions["Enrollment Permissions"] = enrollment_permissions

        object_control_permissions = {"Owner": security.owner}

        rights_mapping = [
            (CertificateRights.GENERIC_ALL, [], "Full Control Principals"),
            (CertificateRights.WRITE_OWNER, [], "Write Owner Principals"),
            (CertificateRights.WRITE_DACL, [], "Write Dacl Principals"),
            (
                CertificateRights.WRITE_PROPERTY,
                [],
                "Write Property Principals",
            ),
        ]

        for sid, rights in security.aces.items():
            rights = rights["rights"]
            sid = regcertipy.utils.sid_to_name(sid)

            for right, principal_list, _ in rights_mapping:
                if right in rights:
                    principal_list.append(sid)

        for _, rights, name in rights_mapping:
            if len(rights) > 0:
                object_control_permissions[name] = rights

        if len(object_control_permissions) > 0:
            permissions["Object Control Permissions"] = object_control_permissions

        return permissions

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
                "Permissions": self.permissions,
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
