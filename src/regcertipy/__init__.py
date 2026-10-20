import argparse

from certipy.commands.find import Find
from regcertipy.models import CertTemplate
from regcertipy.models.cert_template import MockLDAPEntry
from regcertipy.parsers import RegfileParser, RegBofParser
from datetime import datetime
from .utils import sid_to_name, filetime_bytes_to_str
import functools


class MockTarget:
    username = None


class MockLDAPConnection:
    user_sids = set()

    def __init__(self, sid_file, neo4j_driver=None, use_owned_sids=False):
        self.neo4j_driver = neo4j_driver
        if sid_file:
            with open(sid_file) as f:
                for line in f:
                    self.user_sids.add(line.strip())
        if use_owned_sids and self.neo4j_driver:
            self.get_owned_sids()

    def get_user_sids(self, *args, **kwargs):
        return self.user_sids

    def get_owned_sids(self):
        records_agi, _, _ = self.neo4j_driver.execute_query(
            "MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE COALESCE(u.system_tags, '') CONTAINS 'owned' return u.objectid,g.objectid"
        )
        records_agt, _, _ = self.neo4j_driver.execute_query(
            "MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE (u:Tag_Owned) return u.objectid,g.objectid"
        )
        records = [*records_agi, *records_agt]

        for record in records:
            self.user_sids.add(record["u.objectid"])
            self.user_sids.add(record["g.objectid"])

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
    parser.add_argument("-e", "--enabled-file", help="File containing the enabled templates")
    parser.add_argument("--ca-name", default="UNKNOWN", help="Name of the CA to associate with the enabled templates")
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

    cache_key = (
        "HKEY_USERS\\.DEFAULT\\Software\\Microsoft"
        "\\Cryptography\\CertificateTemplateCache"
    )

    templates = []

    for key, dct in parser.to_dict().items():
        if key.casefold() == cache_key.casefold():
            for name in ["Timestamp", "TimestampAfter"]:
                when = filetime_bytes_to_str(dct.get(name))
                if when:
                    print(f"[*] Template cache {name}: {when}")
            continue

        if not key.casefold().startswith(cache_key.casefold()):
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

    if args.enabled_file:
        with open(args.enabled_file) as f:
            enabled_templates = [line.strip() for line in f]

        ca = MockLDAPEntry(
            {
                "name": args.ca_name,
                "objectGUID": "{00000000-0000-0000-0000-000000000000}",
                "certificateTemplates": enabled_templates,
            }
        )
        enabled_count = find._link_cas_and_templates([ca], templates)
        for template in templates:
            template.set("enabled", bool(template.get("cas")))

        print(f"[*] Found {enabled_count} enabled certificate templates")

    for template in templates:
        user_can_enroll, enrollable_sids = find.can_user_enroll_in_template(template)
        template.set("Can Enroll", user_can_enroll)
        template.set("Enrollable SIDs", [sid_to_name(sid) for sid in enrollable_sids])

    prefix = datetime.now().strftime("%Y%m%d%H%M%S") if not args.output else args.output
    find._save_output(templates=templates, cas=[], oids=[], prefix=prefix)


if __name__ == "__main__":
    main()
