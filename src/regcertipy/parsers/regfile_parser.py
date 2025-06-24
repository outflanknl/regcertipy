import configparser
import re


class RegfileParser(configparser.RawConfigParser):
    def __init__(self, regfile: str):
        super().__init__()

        with open(regfile, encoding="utf-16-le", newline="\r\n") as f:
            firstline = f.readline()

            if "Windows Registry Editor Version" not in firstline:
                raise Exception("Error reading header magic string from file")

            content = f.read()

        # Normalize content.
        content = content.replace("\x0d", "")
        content = re.sub(r"^([^\"\[\ \@])", r"  \1", content, flags=re.M)
        content = re.sub(r'^"$', "", content, flags=re.M)

        self.read_string(content)

    def optionxform(self, optionstr):
        # Prevent keys from becoming lowercase.
        return optionstr

    def to_dict(self):
        resulting_dict = {}

        for section in self.sections():
            resulting_dict[section] = {}

            for k, v in self.items(section):
                stripped_key = k.lstrip('"').rstrip('"')

                if re.match(r"hex(\(\d+\))?:", v):
                    v = RegfileParser.hex_to_bytes(v)
                elif v.startswith("dword:"):
                    v = RegfileParser.dword_to_int(v)
                elif isinstance(v, str) and v.startswith('"') and v.endswith('"'):
                    v = v.lstrip('"').rstrip('"')

                # It is hard to distinguish REG_MULTI_SZ, so we just hardcode some keys that we know have this type
                if stripped_key in [
                    "ExtKeyUsageSyntax",
                    "msPKI-RA-Application-Policies",
                    "msPKI-Cert-Template-OID",
                    "msPKI-Certificate-Policy",
                ]:
                    v = v.decode("utf-16-le").rstrip("\0\0").split("\0")

                resulting_dict[section][stripped_key] = v

        return resulting_dict

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        hex_str = re.sub(r"hex(\(\d+\))?:", "", hex_str)
        hex_str = hex_str.replace(",\\", "")
        hex_str = hex_str.replace(",", "")
        hex_str = hex_str.replace("\n", "")
        return bytes.fromhex(hex_str)

    @staticmethod
    def dword_to_int(dword_str: str) -> int:
        dword_str = dword_str.replace("dword:", "")
        return int(dword_str, 16)
