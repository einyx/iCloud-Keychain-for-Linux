"""CKKS record fetch: pull the iCloud Keychain zone records (tlkshare / synckey / item /
currentitem) via a CloudKit RecordRetrieveChanges op per zone. See RESEARCH.md "transport/ckks.py"."""

from __future__ import annotations

import dataclasses
import struct

from ..proto.codec import Writer, decode_fields, first, first_str


@dataclasses.dataclass
class CKDate:
    """A CloudKit Date value - kept distinct from a plain double so the item AAD encodes it
    as RFC3339 rather than as a number."""
    time: float   # seconds (UNIX)


# Keychain CKKS zones (private DB). "Passwords" + "Manatee" hold web credentials.
KEYCHAIN_ZONES = (
    "Passwords", "Manatee", "Engram", "SecureObjectSync", "ProtectedCloudStorage",
    "CreditCards", "ApplePay", "WiFi", "Home", "Groups", "Contacts", "Mail",
    "LimitedPeersAllowed", "SE-PTC", "Photos",
)

ID_TYPE_RECORD_ZONE = 6
ID_TYPE_USER = 7

OP_TYPE_RECORD_RETRIEVE_CHANGES = 213
FIELD_RETRIEVE_CHANGES = 213

# --- write path -------------------------------------------------------------
# The CloudKitDaemon message layout (field numbers) comes from the schema in
# `doug-leith/ios-protobuf-decoding` (ios_decoder/protos/CloudKitDaemon/ckdp.proto),
# reconstructed from CloudKitDaemon's binary. The names used here are the ones the
# .proto uses; see RESEARCH.md "transport/ckks.py".

OP_TYPE_RECORD_SAVE = 210
FIELD_RECORD_SAVE = 210
OP_TYPE_RECORD_DELETE = 214
FIELD_RECORD_DELETE = 214

# CKDPIdentifier.Type
ID_TYPE_RECORD = 1

# CKDPRecordFieldValue.Type
VALUE_TYPE_BYTES = 1
VALUE_TYPE_STRING = 3
VALUE_TYPE_REFERENCE = 5
VALUE_TYPE_INT64 = 7

# CKDPRecordReference.Type - the keychain's parent links use VALIDATING
REFERENCE_TYPE_VALIDATING = 3

# CKDPRecordPermission
PERMISSION_READ_WRITE = 2

# CKDPRecordSaveRequest.SaveSemantics
SAVE_SEMANTICS_FAIL_IF_OUTDATED = 1
SAVE_SEMANTICS_FAIL_IF_EXISTS = 2      # create: fail if the record is already there
SAVE_SEMANTICS_OVERRIDE = 3            # update: overwrite whatever is there


def _identifier(name: str, type_: int) -> bytes:
    return Writer().string(1, name).uint64(2, type_).finish()


def record_zone_identifier(zone: str, user_id: str) -> bytes:
    return (Writer()
            .message(1, _identifier(zone, ID_TYPE_RECORD_ZONE))
            .message(2, _identifier(user_id, ID_TYPE_USER))
            .finish())


def build_retrieve_changes_request(zone_identifier: bytes,
                                   continuation_token: bytes | None = None,
                                   max_changes: int = 500) -> bytes:
    return (Writer()
            .bytes(1, continuation_token)
            .message(2, zone_identifier)
            .uint64(4, max_changes)
            .finish())


def _parse_zone_identifier(raw: bytes) -> dict:
    """RecordZoneIdentifier{value=1 Identifier, ownerIdentifier=2 Identifier} -> {name, owner,
    raw}. `raw` is kept so a record fetch can address the same zone verbatim."""
    f = decode_fields(raw)
    value = first(f, 1)
    owner = first(f, 2)
    return {
        "name": first_str(decode_fields(value), 1) if value is not None else "",
        "owner": first_str(decode_fields(owner), 1) if owner is not None else "",
        "raw": raw,
    }


def parse_zone_changes_response(raw: bytes) -> dict:
    """RetrieveZoneChangesResponse -> {zones, continuation_token, status}. status 2 = done.
    Each zone: {name, owner, change_type, raw} (raw = the RecordZoneIdentifier message)."""
    f = decode_fields(raw)
    zones = []
    for change in f.get(1, []):
        cf = decode_fields(change)
        zid = first(cf, 1)
        if zid is None:
            continue
        info = _parse_zone_identifier(zid)
        info["change_type"] = first(cf, 2, 0)   # 2 = deleted
        zones.append(info)
    return {"zones": zones, "continuation_token": first(f, 2), "status": first(f, 3)}


@dataclasses.dataclass
class CloudKitRecord:
    record_name: str        # identifier value name (usually a UUID)
    type: str               # "item" / "synckey" / "tlkshare" / "currentitem" / ...
    fields: dict            # {field_name: python value}

    def get_bytes(self, name: str) -> bytes | None:
        v = self.fields.get(name)
        return v if isinstance(v, (bytes, bytearray)) else None

    def get_str(self, name: str) -> str | None:
        v = self.fields.get(name)
        return v if isinstance(v, str) else None


def _parse_value(raw: bytes):
    """Record.Field.Value -> python value. Types are preserved so the item AAD encodes each
    correctly: str, bytes, int, float, CKDate."""
    v = decode_fields(raw)
    if 2 in v:
        return first(v, 2)                     # bytesValue
    if 7 in v:
        return first_str(v, 7)                 # stringValue
    if 4 in v:
        return first(v, 4)                     # signedValue (int64)
    if 5 in v:                                 # doubleValue (fixed64, IEEE-754)
        return struct.unpack("<d", first(v, 5).to_bytes(8, "little"))[0]
    if 6 in v:                                 # dateValue: Date{ time(1): double }
        d = decode_fields(first(v, 6))
        if 1 in d:
            return CKDate(struct.unpack("<d", first(d, 1).to_bytes(8, "little"))[0])
    if 9 in v:                                 # referenceValue -> the target record's name,
        ref = decode_fields(first(v, 9))       # e.g. parentkeyref linking synckey->TLK / item->classkey
        rid = first(ref, 2)
        if rid is not None:
            idval = first(decode_fields(rid), 1)
            if idval is not None:
                return first_str(decode_fields(idval), 1)
    return None


def parse_record(raw: bytes) -> CloudKitRecord:
    f = decode_fields(raw)
    rec_id = first(f, 2)
    name = ""
    if rec_id is not None:
        idval = first(decode_fields(rec_id), 1)
        if idval is not None:
            name = first_str(decode_fields(idval), 1) or ""
    type_blob = first(f, 3)
    rtype = first_str(decode_fields(type_blob), 1) if type_blob is not None else ""
    fields = {}
    for fld in f.get(7, []):
        ff = decode_fields(fld)
        ident = first(ff, 1)
        fname = first_str(decode_fields(ident), 1) if ident is not None else None
        val = first(ff, 2)
        if fname is not None and val is not None:
            fields[fname] = _parse_value(val)
    return CloudKitRecord(record_name=name, type=rtype or "", fields=fields)


def parse_retrieve_changes_response(raw: bytes) -> dict:
    """Returns {records, continuation_token, status}. status 1 means another page is available;
    status 3 is the final state token for the zone."""
    f = decode_fields(raw)
    records = []
    for change in f.get(1, []):
        cf = decode_fields(change)
        rec = first(cf, 5)
        if rec is not None:
            records.append(parse_record(rec))
    return {"records": records, "continuation_token": first(f, 2), "status": first(f, 4)}


# --- write path -------------------------------------------------------------
#
# CKDPRecordSaveRequest{record(1), merge(2), fieldsToDeleteIfExistOnMerges(3), etag(4),
#   conflictLoserUpdate(5), saveSemantics(6), zoneProtectionInfoTag(7),
#   recordProtectionInfoTag(8)}
#
# The keychain's zones carry no protection info at all (a zone retrieve shows no
# `protectionInfo`, and no item record has one either), so the two protection-tag
# fields are left unset - they only exist for records the server encrypts itself.


def build_record_identifier(record_name: str, zone: str, user_id: str) -> bytes:
    """CKDPRecordIdentifier{value(1)=Identifier{name, type=RECORD},
    zoneIdentifier(2)=RecordZoneIdentifier{zone, owner=cloudKitUserId}}."""
    return (Writer()
            .message(1, _identifier(record_name, ID_TYPE_RECORD))
            .message(2, record_zone_identifier(zone, user_id))
            .finish())


def build_reference_value(record_name: str, zone: str, user_id: str) -> bytes:
    """A CKDPRecordFieldValue holding a reference to another record (the keychain uses
    these for `parentkeyref`, the pointer at the view's class key)."""
    reference = (Writer()
                 .uint64(1, REFERENCE_TYPE_VALIDATING)
                 .message(2, build_record_identifier(record_name, zone, user_id))
                 .finish())
    return (Writer()
            .uint64(1, VALUE_TYPE_REFERENCE)
            .message(9, reference)
            .finish())


def build_field_value(value) -> bytes:
    """A CKDPRecordFieldValue for a python value: bytes -> BYTES, str -> STRING,
    int -> INT64. The `type` discriminator says what the value *is*, not how it is
    stored, and it is what a reader branches on."""
    if isinstance(value, (bytes, bytearray)):
        return Writer().uint64(1, VALUE_TYPE_BYTES).bytes(2, bytes(value)).finish()
    if isinstance(value, str):
        return Writer().uint64(1, VALUE_TYPE_STRING).string(7, value).finish()
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        return Writer().uint64(1, VALUE_TYPE_INT64).uint64(4, value).finish()
    raise TypeError(f"cannot encode {type(value).__name__} as a CloudKit field value")


def build_record_field(name: str, value) -> bytes:
    """CKDPRecordField{identifier(1)={name}, value(2)}."""
    return (Writer()
            .message(1, Writer().string(1, name).finish())
            .message(2, value)
            .finish())


def build_record(record_name: str, record_type: str, zone: str, user_id: str,
                 fields: list[bytes], *, permission: int = PERMISSION_READ_WRITE) -> bytes:
    """A CKDPRecord: {recordIdentifier(2), type(3), fields(7), permission(15)}.

    `etag`, `createdBy`, `timeStatistics`, `modifiedBy` and friends are server-owned and
    deliberately left out - a create has no etag yet."""
    w = Writer()
    w.message(2, build_record_identifier(record_name, zone, user_id))
    w.message(3, Writer().string(1, record_type).finish())
    for f in fields:
        w.message(7, f)
    w.uint64(15, permission)
    return w.finish()


def build_record_save_request(record: bytes, *, merge: bool = True,
                              save_semantics: int = SAVE_SEMANTICS_FAIL_IF_EXISTS,
                              zone_protection_info_tag: str | None = None,
                              record_protection_info_tag: str | None = None) -> bytes:
    """A CKDPRecordSaveRequest carrying one record.

    `merge` keeps fields the request does not mention - it is the safety net for an
    update, not a licence to send a partial record.
    `save_semantics` 2 (FAIL_IF_EXISTS) creates, 3 (OVERRIDE) updates.
    """
    w = Writer()
    w.message(1, record)
    w.bool(2, merge)
    w.uint64(6, save_semantics)
    w.string(7, zone_protection_info_tag)
    w.string(8, record_protection_info_tag)
    return w.finish()


def parse_record_save_response(raw: bytes) -> dict:
    """A CKDPRecordSaveResponse{etag(2), timeStatistics(3), serverFields(4)} ->
    {etag, record}. The server's copy of the record is what the write actually
    produced, so it - not the request - is the thing to check."""
    f = decode_fields(raw)
    server = first(f, 4)
    return {
        "etag": first_str(f, 2),
        "record": parse_record(server) if server is not None else None,
    }


def build_record_delete_request(record_name: str, zone: str, user_id: str,
                                etag: str | None = None) -> bytes:
    """A CKDPRecordDeleteRequest{recordIdentifier(1), etag(2)} - the rollback path for a
    write that turned out to be wrong."""
    w = Writer()
    w.message(1, build_record_identifier(record_name, zone, user_id))
    w.string(2, etag)
    return w.finish()


def fetch_zone_records(transport, zone: str, user_id: str, *,                       bundle: str = "com.apple.securityd",
                       max_pages: int = 50) -> list:
    """Every record in one zone, paginated. LIVE.

    The keychain's zones are bigger than one page (the Passwords zone holds well
    over 500 records), so a caller that needs the whole zone has to follow the
    continuation token."""
    zid = record_zone_identifier(zone, user_id)
    out: list = []
    continuation = None
    for _ in range(max_pages):
        raw = transport.fetch_records(build_retrieve_changes_request(zid, continuation),
                                      bundle=bundle)
        page = parse_retrieve_changes_response(raw)
        out.extend(page["records"])
        continuation = page.get("continuation_token")
        if page.get("status") != 1 or not continuation:
            break
    return out
