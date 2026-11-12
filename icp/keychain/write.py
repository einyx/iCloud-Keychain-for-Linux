"""Writing new items into the iCloud Keychain.

The read side (see pipeline.py) is: TLKShare -> TLK -> class key -> item key ->
item plist. This module is the other direction: build an item plist, wrap its
item key with the view's class key, encrypt the plist, and assemble the CKKS
record that carries it.

An item lives in a *view* - a CloudKit zone such as "Passwords". The view's class
key is shared with the user's own peers through the sponsor's TLKShare, so a peer
that holds it can add items to that view, which is what Apple's own clients do.
No new TLKShare is needed for an existing view.

The item written here is the classic "Web form password" one: the secret lives in
`v_Data` of an `inet` item whose access group is `com.apple.cfnetwork`. Apple's
current clients still store the password that way - the newer "Password Manager
Metadata" and "Website Metadata" items are *metadata about* a credential, not the
credential - so a classic item is what a reader on any Apple device understands.
"""

from __future__ import annotations

import base64
import os
import plistlib
import uuid as uuid_mod
from datetime import datetime, timezone

from ..errors import AppleError
from ..transport import ckks
from . import crypto as kc
from . import pipeline

# The zone web passwords live in, and the view (class key) inside it they live under.
PASSWORDS_ZONE = "Passwords"
CLASS_A_VIEW = "classA"

# The attribute set of an internet-password item, as Apple's clients write it.
INET_CLASS = "inet"
ACCESS_GROUP_NETWORK = "com.apple.cfnetwork"
AUTH_TYPE_FORM = "form"
DESCRIPTION_FORM = "Web form password"
DEFAULT_COMMENT = "default"
PRIMARY_DOMAIN = "ak"        # every item in the Passwords zone carries this value
PROTOCOL_HTTPS = "htps"
PROTOCOL_HTTP = "http"

# The `uploadver` string says which client wrote the record ("<name> <version> (<build>)").
DEFAULT_UPLOADVER = "icp 0.1.0 (linux)"


class KeychainWriteError(AppleError):
    """A write to the keychain could not be prepared or completed."""


def _now() -> datetime:
    # Apple's keychain dates are naive UTC in the plist (a binary plist date is an
    # offset from 2001-01-01, and the reader hands back a naive datetime), so this
    # one has to be naive too or the plist writer refuses it.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def build_internet_password_item(domain: str, username: str, password: str, *,
                                 title: str | None = None,
                                 notes: str | None = None,
                                 protocol: str | None = None,
                                 path: str = "",
                                 port: int = 0,
                                 access_group: str = ACCESS_GROUP_NETWORK,
                                 now: datetime | None = None) -> dict:
    """The plist an `inet` keychain item carries.

    The attributes are the ones Apple's clients write for an internet password:
    `class`=inet, `atyp`=form, `agrp`=the access group, `v_Data`=the secret,
    `musr`=empty, `pdmn`="ak", `ptcl`=htps/http, `tomb`=0, and `cdat`/`mdat`=the
    modification time (which is how a reader picks the newest version of a
    credential - the Passwords view has no separate "current item" pointer).

    `sha1` is 20 opaque bytes: it is *not* a hash of the password (items with
    identical passwords have different values, so it cannot be one) and nothing
    can verify it, so random bytes reproduce what Apple's clients write.
    """
    now = now or _now()
    if protocol is None:
        protocol = PROTOCOL_HTTPS
    secret = password.encode("utf-8")
    item = {
        "acct": username,
        "agrp": access_group,
        "atyp": AUTH_TYPE_FORM,
        "cdat": now,
        "class": INET_CLASS,
        "desc": DESCRIPTION_FORM,
        "icmt": notes if notes else DEFAULT_COMMENT,
        "labl": title or f"{domain} ({username})",
        "mdat": now,
        "musr": b"",
        "path": path,
        "pdmn": PRIMARY_DOMAIN,
        "port": port,
        "ptcl": protocol,
        "sdmn": "",
        "sha1": os.urandom(20),
        "srvr": domain,
        "tomb": 0,
        "v_Data": secret,
    }
    return item


def build_item_record(item_plist: dict, class_key: bytes, *,
                      parent_key_id: str,
                      zone: str,
                      user_id: str,
                      record_name: str | None = None,
                      encver: int = 2,
                      gen: int = 0,
                      uploadver: str = DEFAULT_UPLOADVER) -> tuple[str, list[bytes]]:
    """Build the CKKS record that carries one item.

    Returns (record name, the record's fields as encoded `CKDPRecordField`s). The
    field set is exactly the one a real item record carries - `data`, `encver`,
    `gen`, `parentkeyref`, `server_suggestDeletion`, `server_wascurrent`,
    `uploadver`, `wrappedkey` - because the record's own fields are what the
    item's authenticated data is computed over: a reader recomputes it from the
    record it fetched, so a field it does not know about would break the check.
    """
    record_name = record_name or str(uuid_mod.uuid4()).upper()
    item_key = os.urandom(64)
    plaintext = plistlib.dumps(item_plist, fmt=plistlib.FMT_BINARY)

    fields = {
        "encver": encver,
        "gen": gen,
        "parentkeyref": parent_key_id,
        "server_suggestDeletion": 0,
        "server_wascurrent": 0,
        "uploadver": uploadver,
        # The item key, wrapped with the view's class key (no associated data).
        "wrappedkey": base64.b64encode(kc.siv_wrap(class_key, item_key)).decode(),
    }
    # The payload is encrypted with the same associated data a reader recomputes.
    aad = pipeline.authenticated_data_v2(record_name, fields, encver=encver, gen=gen,
                                         parent_key_id=parent_key_id)
    fields["data"] = kc.encrypt_item(item_key, plaintext, aad)

    encoded = []
    for name, value in fields.items():
        if name == "parentkeyref":
            encoded.append(ckks.build_record_field(
                name, ckks.build_reference_value(parent_key_id, zone, user_id)))
        else:
            encoded.append(ckks.build_record_field(name, ckks.build_field_value(value)))
    return record_name, encoded


def build_item_record_message(record_name: str, fields: list[bytes], *,
                              zone: str = PASSWORDS_ZONE, user_id: str) -> bytes:
    """The `CKDPRecord` for an `item`."""
    return ckks.build_record(record_name, "item", zone, user_id, fields)


def group_by_type(records) -> dict:
    """{record type: [records]} - the shape the pipeline works with."""
    grouped: dict = {}
    for rec in records:
        grouped.setdefault(rec.type, []).append(rec)
    return grouped


def view_key(records_by_type: dict, tlks: dict, *, view: str = CLASS_A_VIEW) -> tuple[str, bytes]:
    """The class key of a zone's view: (key id, key bytes).

    The `currentkey` record named `classA` points at the class key record (a
    `synckey`), and the class key itself is that synckey unwrapped with the TLK.
    """
    current = next((r for r in records_by_type.get("currentkey", [])
                    if r.record_name == view), None)
    if current is None:
        raise KeychainWriteError(f"no {view!r} view in this zone")
    key_id = current.get_str("parentkeyref")
    if not key_id:
        raise KeychainWriteError(f"the {view!r} view has no class key")
    keys = pipeline.unwrap_class_keys(records_by_type.get("synckey", []), tlks)
    key = keys.get(key_id)
    if key is None:
        raise KeychainWriteError(
            f"cannot unwrap the class key of the {view!r} view - the keychain trust "
            "does not include it yet")
    return key_id, key


def save_internet_password(transport, *, class_key: bytes, class_key_id: str, user_id: str,
                           domain: str, username: str, password: str,
                           zone: str = PASSWORDS_ZONE,
                           title: str | None = None,
                           notes: str | None = None,
                           protocol: str | None = None,
                           path: str = "",
                           port: int = 0,
                           uploadver: str = DEFAULT_UPLOADVER) -> dict:
    """Save one new internet password into the keychain. LIVE.

    Returns {record_name, etag, record} where `record` is the server's copy of the
    record as it now stands."""
    item = build_internet_password_item(domain, username, password, title=title,
                                        notes=notes, protocol=protocol, path=path,
                                        port=port)
    record_name, fields = build_item_record(
        item, class_key, parent_key_id=class_key_id, zone=zone, user_id=user_id,
        uploadver=uploadver)
    record = build_item_record_message(record_name, fields, zone=zone, user_id=user_id)
    request = ckks.build_record_save_request(
        record, merge=True, save_semantics=ckks.SAVE_SEMANTICS_FAIL_IF_EXISTS)
    raw = transport.save_record(request)
    parsed = ckks.parse_record_save_response(raw)
    parsed["record_name"] = record_name
    return parsed


def add_internet_password(client, domain: str, username: str, password: str, *,
                          zone: str = PASSWORDS_ZONE,
                          view: str = CLASS_A_VIEW,
                          title: str | None = None,
                          notes: str | None = None,
                          protocol: str | None = None,
                          path: str = "",
                          port: int = 0) -> dict:
    """Add a password to the keychain, end to end. LIVE.

    Fetches the view's zone, unwraps its class key (through the TLK the sponsor
    shared with this peer), writes the item and saves it.

    `client` is an `octagon.OctagonClient`."""
    from ..octagon import client as octagon

    records = ckks.fetch_zone_records(client.transport, zone, client.user_id)
    by_type = group_by_type(records)

    tlks, _ = client.fetch_recoverable_tlks()
    peer_id = (client.record.get("octagon") or {}).get("peer_id") or ""
    plain = pipeline.unwrap_tlkshares(
        by_type.get("tlkshare", []), peer_id,
        octagon.load_peer_keys(client.record).encryption.private_key)
    key_id, class_key = view_key(by_type, {**plain, **tlks}, view=view)

    result = save_internet_password(
        client.transport, class_key=class_key, class_key_id=key_id,
        user_id=client.user_id, domain=domain, username=username, password=password,
        zone=zone, title=title, notes=notes, protocol=protocol, path=path, port=port)
    # The class key comes back so the caller can re-read and decrypt what was written.
    result["class_key"] = class_key
    result["class_key_id"] = key_id
    return result


def delete_record(transport, *, record_name: str, zone: str, user_id: str,
                  etag: str | None = None) -> bool:
    """Delete a record that was written. LIVE.

    The rollback path: a write that turned out to be wrong (or a test entry that
    should not stay) is removed again."""
    request = ckks.build_record_delete_request(record_name, zone, user_id, etag)
    transport.delete_record(request)
    return True


def verify_saved_record(transport, *, record_name: str, zone: str, user_id: str,
                        class_key: bytes, expected_password: str,
                        expected_username: str | None = None) -> bool:
    """Re-fetch the zone, find the record just written, decrypt it, and check it.

    A save response is not proof - the escrow service reports success for writes
    that addressed nothing. What counts is that the record is there, decrypts, and
    holds what was written."""
    import plistlib as _plistlib

    for rec in ckks.fetch_zone_records(transport, zone, user_id):
        if rec.record_name != record_name or rec.type != "item":
            continue
        data = rec.get_bytes("data")
        wrapped = rec.get_str("wrappedkey")
        if data is None or not wrapped:
            return False
        try:
            item_key = kc.siv_unwrap(class_key, base64.b64decode(wrapped))
            aad = pipeline.authenticated_data_v2(
                rec.record_name, rec.fields, encver=rec.fields.get("encver", 2),
                gen=rec.fields.get("gen", 0), parent_key_id=rec.get_str("parentkeyref"))
            item = _plistlib.loads(kc.decrypt_item(item_key, data, aad))
        except Exception:
            return False
        if item.get("v_Data") != expected_password.encode("utf-8"):
            return False
        if expected_username is not None and item.get("acct") != expected_username:
            return False
        return True
    return False
