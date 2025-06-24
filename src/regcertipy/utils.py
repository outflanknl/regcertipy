from certipy.lib.constants import WELLKNOWN_SIDS, WELLKNOWN_RIDS


def sid_to_name(sid: str):
    res = WELLKNOWN_SIDS.get(sid)
    if res:
        return res[0]
    for rid, res in WELLKNOWN_RIDS.items():
        if sid.endswith(f"-{rid}"):
            return res[0]

    return sid
