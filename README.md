# regcertipy

Parses cached certificate templates from a Windows Registry `.reg` file and displays them in the same style as [Certipy](https://github.com/ly4k/Certipy) does.

## Getting started

We prefer using the [uv package manager](https://docs.astral.sh/uv/), as it will automatically create a virtual environment for you. Alternatively, you can use `pip install regcertipy` within any other Python environment that you manage.

```
$ uv venv
$ source .venv/bin/activate
$ uv pip install regcertipy
$ regcertipy -h
usage: regcertipy [-h] [-s SID_FILE] [-f {.reg,reg_bof}] [-text] [-stdout]
                  [-json] [-csv] [-output prefix] [--neo4j-user NEO4J_USER]
                  [--neo4j-pass NEO4J_PASS] [--neo4j-host NEO4J_HOST]
                  [--neo4j-port NEO4J_PORT] [--use-owned-sids]
                  regfile

Regfile ingestor for Certipy

positional arguments:
  regfile               Path to the .reg file.

options:
  -h, --help            show this help message and exit
  -s SID_FILE, --sid-file SID_FILE
                        File containing the user's SIDs
  -f {.reg,reg_bof}, --input-format {.reg,reg_bof}
                        Format of input file

output options:
  -text                 Output result as formatted text file
  -stdout               Output result as text directly to console
  -json                 Output result as JSON
  -csv                  Output result as CSV
  -output prefix        Filename prefix for writing results to

BloodHound:
  --neo4j-user NEO4J_USER
                        Username for neo4j
  --neo4j-pass NEO4J_PASS
                        Password for neo4j
  --neo4j-host NEO4J_HOST
                        Host for neo4j
  --neo4j-port NEO4J_PORT
                        Port for neo4j
  --use-owned-sids      Use the SIDs of all owned principals as the user SIDs
```

Use regedit.exe to export the keys under `HKEY_USERS\.DEFAULT\Software\Microsoft\Cryptography\CertificateTemplateCache\`. Then, the .reg file can be fed into regcertipy with: regcertipy <regfile>.

![Example of how to export a .reg file](resources/regedit.png)

Alternatively, it is possible to parse output the Outflank C2 `reg query` command by specifying the `-f reg_bof` flag. This parses the following (truncated) output.

```
[01/01/1970 12:34:56 PM] (finished) Outflank > reg query -r HKEY_USERS\.DEFAULT\Software\Microsoft\Cryptography\CertificateTemplateCache

Reg Key:   HKEY_USERS\.DEFAULT\Software\Microsoft\Cryptography\CertificateTemplateCache

Reg Value: TimestampAfter
Reg Type:  REG_BINARY
Reg Data:  86F63B1D13E7DB01

Reg Value: Timestamp
Reg Type:  REG_BINARY
Reg Data:  86F63B1D13E7DB01

Reg Key:   HKEY_USERS\.DEFAULT\Software\Microsoft\Cryptography\CertificateTemplateCache\Administrator

Reg Value: DisplayName
Reg Type:  REG_SZ
Reg Data:  Administrator

Reg Value: SupportedCSPs
Reg Type:  REG_MULTI_SZ
Reg Data:  Microsoft Enhanced Cryptographic Provider v1.0 Microsoft Base Cryptographic Provider v1.0                                                                                             

Reg Value: ExtKeyUsageSyntax
Reg Type:  REG_MULTI_SZ
Reg Data:  1.3.6.1.4.1.311.10.3.1 1.3.6.1.4.1.311.10.3.4 1.3.6.1.5.5.7.3.4 1.3.6.1.5.5.7.3.2

[...]
```

### SIDs

Because `regcertipy` is intended for offline usage, SIDs cannot be dynamically resolved. Therefore, `regcertipy` includes a couple of options that can be used for offline SID information.

Firstly, the `--sid-file` flag can be used to provide a list of SIDs that the user is a member of. This list can be obtained from BloodHound or other tools.

Secondly, `regcertipy` can use a `neo4j` connection to dynamically resolve SIDs using BloodHound's database. This, combined with the `--use-owned-sids` command can help you find vulnerable templates exploitable by objects marked as owned in BloodHound.

## Development

Note that we use the [Black code formatter](https://black.readthedocs.io/en/stable/) for code formatting. Moreover, we use the Git Flow branching model, meaning that we actively develop on the "develop" branch, and merge to the "main" branch (& tag it) when a new release is made, making the "main" branch the production branch.

```
$ uv sync --dev # Also installs the Black code formatter.
$ uv run black . # To format the current code base.
$ uv run regcertipy -h
usage: regcertipy [-h] [-s SID_FILE] [-f {.reg,reg_bof}] [-text] [-stdout]
                  [-json] [-csv] [-output prefix] [--neo4j-user NEO4J_USER]
                  [--neo4j-pass NEO4J_PASS] [--neo4j-host NEO4J_HOST]
                  [--neo4j-port NEO4J_PORT] [--use-owned-sids]
                  regfile

Regfile ingestor for Certipy

positional arguments:
  regfile               Path to the .reg file.

options:
  -h, --help            show this help message and exit
  -s SID_FILE, --sid-file SID_FILE
                        File containing the user's SIDs
  -f {.reg,reg_bof}, --input-format {.reg,reg_bof}
                        Format of input file

output options:
  -text                 Output result as formatted text file
  -stdout               Output result as text directly to console
  -json                 Output result as JSON
  -csv                  Output result as CSV
  -output prefix        Filename prefix for writing results to

BloodHound:
  --neo4j-user NEO4J_USER
                        Username for neo4j
  --neo4j-pass NEO4J_PASS
                        Password for neo4j
  --neo4j-host NEO4J_HOST
                        Host for neo4j
  --neo4j-port NEO4J_PORT
                        Port for neo4j
  --use-owned-sids      Use the SIDs of all owned principals as the user SIDs
```

You can also run the `__init__.py` or `__main.py__` Python file in your favourite debugger.