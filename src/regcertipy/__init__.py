import argparse

from certipy.lib.formatting import pretty_print
from certipy.commands.find import Find
from regcertipy.models import CertTemplate
from regcertipy.parsers import RegfileParser
from datetime import datetime
from .utils import sid_to_name
from collections import OrderedDict


class MockTarget:
    username = None


class MockLDAPConnection:
    user_sids = []

    def __init__(self, sid_file):
        if sid_file:
            with open(sid_file) as f:
                for line in f:
                    self.user_sids.append(line[:-1])

    def get_user_sids(self, *args, **kwargs):
        return self.user_sids

    def lookup_sid(self, sid, **kwargs):
        return {"name": sid_to_name(sid)}


class MyFind(Find):
    def get_template_properties(self, template, template_properties):
        template_properties = super().get_template_properties(
            template, template_properties
        )
        for key in ["Template OIDs"]:
            template_oids = template.get(key)
            if template_oids:
                template_properties[key] = template_oids

        return template_properties


def main():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Regfile ingestor for Certipy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("regfile", help="Path to the .reg file.")
    parser.add_argument("-s", "--sid-file", help="File containing the user's SIDs")
    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-text",
        action="store_true",
        help="Output result as formatted text file",
    )
    output_group.add_argument(
        "-stdout",
        action="store_true",
        help="Output result as text directly to console",
    )
    output_group.add_argument(
        "-json",
        action="store_true",
        help="Output result as JSON",
    )
    output_group.add_argument(
        "-csv",
        action="store_true",
        help="Output result as CSV",
    )
    output_group.add_argument(
        "-output",
        action="store",
        metavar="prefix",
        help="Filename prefix for writing results to",
    )
    args = parser.parse_args()

    parser = RegfileParser(args.regfile)

    templates = []

    for key, dct in parser.to_dict().items():
        if not key.startswith(
            "HKEY_USERS\\.DEFAULT\\Software\\Microsoft"
            "\\Cryptography\\CertificateTemplateCache\\"
        ):
            continue

        name = key.split("\\")[-1]

        template = CertTemplate(name, dct)
        templates.append(template)

    print(f"[*] Found {len(templates)} templates in the registry")

    templates = [template.to_dict() for template in templates]

    find = MyFind(
        target=MockTarget(),
        connection=MockLDAPConnection(args.sid_file),
        stdout=args.stdout,
        text=args.text,
        json=args.json,
    )
    for template in templates:
        user_can_enroll, enrollable_sids = find.can_user_enroll_in_template(template)
        template.set("Can Enroll", user_can_enroll)
        template.set("Enrollable SIDs", [sid_to_name(sid) for sid in enrollable_sids])
        prefix = (
            datetime.now().strftime("%Y%m%d%H%M%S") if not args.output else args.output
        )
    find._save_output(templates=templates, cas=[], oids=[], prefix=prefix)


if __name__ == "__main__":
    main()
