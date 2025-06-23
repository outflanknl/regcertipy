from typing import Dict

import regcertipy.utils
from certipy.commands.find import filetime_to_str
from certipy.lib.constants import (
    CERTIFICATE_RIGHTS,
    EXTENDED_RIGHTS_NAME_MAP,
    MS_PKI_CERTIFICATE_NAME_FLAG,
    MS_PKI_ENROLLMENT_FLAG,
    OID_TO_STR_MAP,
)
from certipy.lib.security import CertifcateSecurity


class CertTemplate:
    def __init__(self, name: str, data: Dict):
        self.data = data

        self.name = name
        self.display_name = self.data["DisplayName"]
        self.oid = (
            self.data["msPKI-Cert-Template-OID"].decode("utf-16-le").rstrip("\0\0")
        )
        self.validity_period = filetime_to_str(self.data["ValidityPeriod"])
        self.renewal_period = filetime_to_str(self.data["RenewalOverlap"])
        self.name_flags = MS_PKI_CERTIFICATE_NAME_FLAG(
            self.data["msPKI-Certificate-Name-Flag"]
        )

        self.enrollment_flags = MS_PKI_ENROLLMENT_FLAG(
            self.data["msPKI-Enrollment-Flag"]
        )
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

        self.permissions = self._build_permissions(self.data["Security"])

    @staticmethod
    def _build_permissions(security_dict: Dict):
        security = CertifcateSecurity(security_dict)

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
            (CERTIFICATE_RIGHTS.GENERIC_ALL, [], "Full Control Principals"),
            (CERTIFICATE_RIGHTS.WRITE_OWNER, [], "Write Owner Principals"),
            (CERTIFICATE_RIGHTS.WRITE_DACL, [], "Write Dacl Principals"),
            (
                CERTIFICATE_RIGHTS.WRITE_PROPERTY,
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

    def to_dict(self):
        return {
            "Name": self.name,
            "Friendly Name": self.display_name,
            "Template OID": self.oid,
            "Validity Period": self.validity_period,
            "Renewal Period": self.renewal_period,
            "Name Flags": self.name_flags,
            "Enrollment Flags": self.enrollment_flags,
            "Signatures Required": self.signatures_required,
            "Extended Key Usage": self.extended_key_usage,
            "Permissions": self.permissions,
        }
