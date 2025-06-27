import configparser
import re
from io import StringIO
from .regfile_parser import RegfileParser

offset = 11


class RegBofParser(configparser.RawConfigParser):
    def __init__(self, output: str):
        super().__init__()

        content = StringIO()
        with open(output) as f:
            for i, line in enumerate(f):
                if line.startswith("Reg Key"):
                    key = line[offset:-1]
                    if i != 0:
                        content.write("\n")
                    content.write(("[" + key + "]\n"))
                elif line.startswith("Reg Value"):
                    value = line[offset:-1]
                elif line.startswith("Reg Type"):
                    type = line[offset:-1]
                elif line.startswith("Reg Data"):
                    data = line[offset:-1].strip()
                    content.write(f"{value}={type}:{data}\n")

        content = content.getvalue()
        self.read_string(content)

    def optionxform(self, optionstr):
        # Prevent keys from becoming lowercase.
        return optionstr

    def to_dict(self):
        resulting_dict = {}

        for section in self.sections():
            resulting_dict[section] = {}

            for k, v in self.items(section):
                reg_type, _, data = v.partition(":")

                if reg_type == "REG_BINARY":
                    data = bytes.fromhex(data)
                elif reg_type == "REG_DWORD":
                    data = int(data, 16)
                elif reg_type == "REG_MULTI_SZ":
                    # The reg query bof does not correctly encode REG_MULTI_SZ, since \0 is replaced by spaces.
                    # We need to guess based on the key how we should split.
                    # But for most keys, splitting by ' ' is fine.
                    # An exception is SupportedCSPs, but this key is not interpreted by regcertipy
                    data = data.split(" ")

                resulting_dict[section][k] = data

        return resulting_dict
