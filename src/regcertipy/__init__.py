import argparse

from certipy.lib.formatting import pretty_print
from regcertipy.models import CertTemplate
from regcertipy.parsers import RegfileParser


def main():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Regfile ingestor for Certipy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("regfile", help="Path to the .reg file.")
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

    for template in templates:
        pretty_print(template.to_dict())


if __name__ == "__main__":
    main()
