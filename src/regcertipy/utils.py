def sid_to_name(sid: str):
    if sid.endswith("-500"):
        return "Administrator"
    if sid.endswith("-501"):
        return "Guest"
    if sid.endswith("-502"):
        return "KRBTGT"
    if sid.endswith("-512"):
        return "Domain Admins"
    if sid.endswith("-513"):
        return "Domain Users"
    if sid.endswith("-514"):
        return "Domain Guests"
    if sid.endswith("-515"):
        return "Domain Computers"
    if sid.endswith("-516"):
        return "Domain Controllers"
    if sid.endswith("-517"):
        return "Cert Publishers"
    if sid.endswith("-518"):
        return "Schema Admins"
    if sid.endswith("-519"):
        return "Enterprise Admins"
    if sid.endswith("-520"):
        return "Group Policy Creator Owners"
    if sid.endswith("-553"):
        return "RAS and IAS Servers"

    return sid
