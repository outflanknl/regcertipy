from datetime import datetime, timedelta, timezone

from certipy.lib.constants import WELLKNOWN_SIDS, WELLKNOWN_RIDS

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_bytes_to_str(data):
    if not data:
        return None
    if isinstance(data, (bytes, bytearray)):
        if len(data) < 8:
            return None
        value = int.from_bytes(bytes(data[:8]), "little")
    else:
        value = int(data)
    if value == 0:
        return None
    return (_FILETIME_EPOCH + timedelta(microseconds=value / 10)).strftime(
        "%d/%m/%Y %H:%M:%S UTC"
    )


def sid_to_name(sid: str):
    res = WELLKNOWN_SIDS.get(sid)
    if res:
        return res[0]
    for rid, res in WELLKNOWN_RIDS.items():
        if sid.endswith(f"-{rid}"):
            return res[0]

    return sid
