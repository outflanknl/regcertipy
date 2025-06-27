import argparse

from certipy.commands.find import Find
from regcertipy.models import CertTemplate
from regcertipy.parsers import RegfileParser, RegBofParser
from datetime import datetime
from .utils import sid_to_name
import functools


class MockTarget:
    username = None


class MockLDAPConnection:
    user_sids = []

    def __init__(self, sid_file, neo4j_driver=None, use_owned_sids=False):
        self.neo4j_driver = neo4j_driver
        if sid_file:
            with open(sid_file) as f:
                for line in f:
                    self.user_sids.append(line[:-1])
        if use_owned_sids and self.neo4j_driver:
            self.get_owned_sids()

    def get_user_sids(self, *args, **kwargs):
        return self.user_sids

    def get_owned_sids(self):
        records, _, _ = self.neo4j_driver.execute_query(
            "MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE COALESCE(u.system_tags, '') CONTAINS 'owned' return g.objectid"
        )
        for record in records:
            self.user_sids.append(record["g.objectid"])

    @functools.cache
    def lookup_sid(self, sid, **kwargs):
        name = sid_to_name(sid)
        if name != sid:
            return {"name": name}
        if self.neo4j_driver:
            records, _, _ = self.neo4j_driver.execute_query(
                "MATCH (g {objectid:'%s'}) return g.name" % (sid,)
            )
            if records:
                return {"name": records[0]["g.name"]}
        return {"name": name}


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
    parser.add_argument(
        "-f",
        "--input-format",
        choices=[".reg", "reg_bof"],
        help="Format of input file",
        default=".reg",
    )
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

    bloodhound = parser.add_argument_group("BloodHound")
    bloodhound.add_argument("--neo4j-user", help="Username for neo4j")
    bloodhound.add_argument("--neo4j-pass", help="Password for neo4j")
    bloodhound.add_argument("--neo4j-host", help="Host for neo4j", default="localhost")
    bloodhound.add_argument("--neo4j-port", help="Port for neo4j", default=7687)
    bloodhound.add_argument(
        "--use-owned-sids",
        help="Use the SIDs of all owned principals as the user SIDs",
        action="store_true",
    )
    args = parser.parse_args()

    if args.neo4j_user and args.neo4j_pass:
        from neo4j import GraphDatabase

        neo4j_driver = GraphDatabase.driver(
            f"neo4j://{args.neo4j_host}:{args.neo4j_port}",
            auth=(args.neo4j_user, args.neo4j_pass),
        )
    else:
        neo4j_driver = None

    if args.input_format == ".reg":
        parser = RegfileParser(args.regfile)
    elif args.input_format == "reg_bof":
        parser = RegBofParser(args.regfile)

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
        connection=MockLDAPConnection(
            args.sid_file, neo4j_driver=neo4j_driver, use_owned_sids=args.use_owned_sids
        ),
        stdout=args.stdout,
        text=args.text,
        json=args.json,
    )

    for template in templates:
        user_can_enroll, enrollable_sids = find.can_user_enroll_in_template(template)
        template.set("Can Enroll", user_can_enroll)
        template.set("Enrollable SIDs", [sid_to_name(sid) for sid in enrollable_sids])

    prefix = datetime.now().strftime("%Y%m%d%H%M%S") if not args.output else args.output
    find._save_output(templates=templates, cas=[], oids=[], prefix=prefix)


if __name__ == "__main__":
    main()
