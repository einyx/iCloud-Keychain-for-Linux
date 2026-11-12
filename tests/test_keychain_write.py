"""Offline tests for the keychain write path.

No network, no real keys: a synthetic class key stands in for the view's, and
the round trip is checked the same way a reader would check it - take the
record apart, unwrap the item key with the class key, recompute the
authenticated data from the record's own fields, and decrypt.
"""

import base64
import plistlib
import unittest

from icp.keychain import crypto as kc
from icp.keychain import pipeline
from icp.keychain import write as kcwrite
from icp.proto.codec import decode_fields, first, first_str
from icp.transport import ckks

CLASS_KEY = bytes(range(64))          # a stand-in for the view's 64-byte class key
PARENT_ID = "17D00B76-793D-442D-90CB-7006CFF11392"
ZONE = "Passwords"
USER_ID = "_0d5fab973e7926ef9590542af16f5c4d"


def _build(domain="example.com", username="alice", password="hunter2", **kw):
    item = kcwrite.build_internet_password_item(domain, username, password, **kw)
    name, fields = kcwrite.build_item_record(
        item, CLASS_KEY, parent_key_id=PARENT_ID, zone=ZONE, user_id=USER_ID,
        record_name="34C5FD0E-695C-4D18-8311-7E0DAF21C94E")
    record = kcwrite.build_item_record_message(name, fields, zone=ZONE, user_id=USER_ID)
    return name, record


class ItemPlistTests(unittest.TestCase):
    def test_attribute_set_matches_apple(self):
        item = kcwrite.build_internet_password_item("example.com", "alice", "hunter2")
        self.assertEqual(item["class"], "inet")
        self.assertEqual(item["atyp"], "form")
        self.assertEqual(item["agrp"], "com.apple.cfnetwork")
        self.assertEqual(item["desc"], "Web form password")
        self.assertEqual(item["icmt"], "default")
        self.assertEqual(item["pdmn"], "ak")
        self.assertEqual(item["ptcl"], "htps")
        self.assertEqual(item["tomb"], 0)
        self.assertEqual(item["srvr"], "example.com")
        self.assertEqual(item["acct"], "alice")
        self.assertEqual(item["v_Data"], b"hunter2")
        self.assertEqual(item["labl"], "example.com (alice)")

    def test_label_override_and_notes(self):
        item = kcwrite.build_internet_password_item("example.com", "alice", "hunter2",
                                                     title="My label", notes="a note")
        self.assertEqual(item["labl"], "My label")
        self.assertEqual(item["icmt"], "a note")

    def test_sha1_is_opaque_not_the_password_hash(self):
        # Apple's own items carry a 20-byte `sha1` that is NOT a hash of the password
        # (items with identical passwords carry different values, so it cannot be one)
        # and nothing can verify it - so it is opaque, and random bytes match it.
        import hashlib
        item = kcwrite.build_internet_password_item("example.com", "alice", "hunter2")
        self.assertEqual(len(item["sha1"]), 20)
        self.assertNotEqual(item["sha1"], hashlib.sha1(b"hunter2").digest())
        other = kcwrite.build_internet_password_item("example.com", "alice", "hunter2")
        self.assertNotEqual(item["sha1"], other["sha1"])   # per item, not per password

    def test_musr_is_empty_like_apples(self):
        item = kcwrite.build_internet_password_item("example.com", "alice", "hunter2")
        self.assertEqual(item["musr"], b"")


class RecordRoundTripTests(unittest.TestCase):
    def test_record_decodes_to_the_record_we_wrote(self):
        name, record = _build()
        parsed = ckks.parse_record(record)
        self.assertEqual(parsed.record_name, "34C5FD0E-695C-4D18-8311-7E0DAF21C94E")
        self.assertEqual(parsed.type, "item")
        self.assertEqual(sorted(parsed.fields),
                         ["data", "encver", "gen", "parentkeyref", "server_suggestDeletion",
                          "server_wascurrent", "uploadver", "wrappedkey"])
        self.assertEqual(parsed.get_str("parentkeyref"), PARENT_ID)
        self.assertEqual(parsed.fields["encver"], 2)
        self.assertEqual(parsed.fields["gen"], 0)
        self.assertEqual(parsed.fields["server_wascurrent"], 0)
        self.assertEqual(parsed.fields["server_suggestDeletion"], 0)

    def test_a_reader_can_unwrap_and_decrypt_the_item(self):
        name, record = _build(password="s3cr3t")
        parsed = ckks.parse_record(record)

        item_key = kc.siv_unwrap(CLASS_KEY, base64.b64decode(parsed.get_str("wrappedkey")))
        aad = pipeline.authenticated_data_v2(
            parsed.record_name, parsed.fields,
            encver=parsed.fields["encver"], gen=parsed.fields["gen"],
            parent_key_id=parsed.get_str("parentkeyref"))
        item = plistlib.loads(kc.decrypt_item(item_key, parsed.get_bytes("data"), aad))
        self.assertEqual(item["v_Data"], b"s3cr3t")
        self.assertEqual(item["srvr"], "example.com")
        self.assertEqual(item["acct"], "alice")

    def test_tampering_with_an_authenticated_field_breaks_the_decryption(self):
        # The payload is authenticated over the record's own identity - its name, the
        # class key it hangs under, the encryption version - so moving it breaks it.
        name, record = _build()
        parsed = ckks.parse_record(record)
        item_key = kc.siv_unwrap(CLASS_KEY, base64.b64decode(parsed.get_str("wrappedkey")))
        aad = pipeline.authenticated_data_v2(
            parsed.record_name, parsed.fields,
            encver=parsed.fields["encver"], gen=parsed.fields["gen"],
            parent_key_id=parsed.get_str("parentkeyref"))
        # The authentic data decrypts ...
        self.assertTrue(kc.decrypt_item(item_key, parsed.get_bytes("data"), aad))
        # ... a different record name does not ...
        moved = pipeline.authenticated_data_v2(
            "00000000-0000-0000-0000-000000000000", parsed.fields,
            encver=parsed.fields["encver"], gen=parsed.fields["gen"],
            parent_key_id=parsed.get_str("parentkeyref"))
        with self.assertRaises(Exception):
            kc.decrypt_item(item_key, parsed.get_bytes("data"), moved)
        # ... and neither does a different class key.
        other_parent = pipeline.authenticated_data_v2(
            parsed.record_name, parsed.fields,
            encver=parsed.fields["encver"], gen=parsed.fields["gen"],
            parent_key_id="66CDE7E6-6911-4F68-AEDB-B22374C70526")
        with self.assertRaises(Exception):
            kc.decrypt_item(item_key, parsed.get_bytes("data"), other_parent)

    def test_the_class_key_is_needed(self):
        name, record = _build()
        parsed = ckks.parse_record(record)
        with self.assertRaises(Exception):
            kc.siv_unwrap(bytes(64), base64.b64decode(parsed.get_str("wrappedkey")))


class RecordMessageTests(unittest.TestCase):
    def test_record_message_layout(self):
        name, record = _build()
        f = decode_fields(record)
        self.assertEqual(sorted(f.keys()), [2, 3, 7, 15])   # id, type, fields, permission
        self.assertEqual(first(f, 15), ckks.PERMISSION_READ_WRITE)

        ident = decode_fields(first(f, 2))
        self.assertEqual(sorted(ident.keys()), [1, 2])
        value = decode_fields(first(ident, 1))
        self.assertEqual(first_str(value, 1), "34C5FD0E-695C-4D18-8311-7E0DAF21C94E")
        self.assertEqual(first(value, 2), ckks.ID_TYPE_RECORD)
        zone = decode_fields(first(ident, 2))
        zvalue = decode_fields(first(zone, 1))
        self.assertEqual(first_str(zvalue, 1), ZONE)
        self.assertEqual(first(zvalue, 2), ckks.ID_TYPE_RECORD_ZONE)
        owner = decode_fields(first(zone, 2))
        self.assertEqual(first_str(owner, 1), USER_ID)
        self.assertEqual(first(owner, 2), ckks.ID_TYPE_USER)

    def test_parentkeyref_is_a_reference(self):
        name, record = _build()
        f = decode_fields(record)
        for fld in f.get(7, []):
            ff = decode_fields(fld)
            fname = first_str(decode_fields(first(ff, 1)), 1)
            if fname != "parentkeyref":
                continue
            value = decode_fields(first(ff, 2))
            self.assertEqual(first(value, 1), ckks.VALUE_TYPE_REFERENCE)
            ref = decode_fields(first(value, 9))
            self.assertEqual(first(ref, 1), ckks.REFERENCE_TYPE_VALIDATING)
            ref_id = decode_fields(first(ref, 2))
            rid = decode_fields(first(ref_id, 1))
            self.assertEqual(first_str(rid, 1), PARENT_ID)
            return
        self.fail("no parentkeyref field")


class SaveRequestTests(unittest.TestCase):
    def test_save_request_layout(self):
        name, record = _build()
        request = ckks.build_record_save_request(
            record, merge=True, save_semantics=ckks.SAVE_SEMANTICS_FAIL_IF_EXISTS)
        f = decode_fields(request)
        self.assertEqual(sorted(f.keys()), [1, 2, 6])
        self.assertEqual(first(f, 2), 1)                                  # merge
        self.assertEqual(first(f, 6), ckks.SAVE_SEMANTICS_FAIL_IF_EXISTS)  # create
        self.assertEqual(first(f, 1), record)

    def test_protection_tags_are_optional(self):
        request = ckks.build_record_save_request(
            b"", merge=True, save_semantics=ckks.SAVE_SEMANTICS_OVERRIDE,
            zone_protection_info_tag="z", record_protection_info_tag="r")
        f = decode_fields(request)
        self.assertEqual(first_str(f, 7), "z")
        self.assertEqual(first_str(f, 8), "r")
        self.assertEqual(first(f, 6), ckks.SAVE_SEMANTICS_OVERRIDE)


class ViewKeyTests(unittest.TestCase):
    def test_view_key_follows_currentkey_to_synckey(self):
        # currentkey 'classA' -> parentkeyref = the class key record; the synckey's
        # wrappedkey is the class key wrapped with the TLK.
        tlk = b"T" * 32
        class_key = b"C" * 64
        synckey = ckks.CloudKitRecord(
            record_name=PARENT_ID, type="synckey",
            fields={"class": "classA", "parentkeyref": "TLK-ID",
                    "wrappedkey": base64.b64encode(kc.siv_wrap(tlk, class_key)).decode()})
        currentkey = ckks.CloudKitRecord(
            record_name="classA", type="currentkey", fields={"parentkeyref": PARENT_ID})
        by_type = {"synckey": [synckey], "currentkey": [currentkey]}

        key_id, key = kcwrite.view_key(by_type, {"TLK-ID": tlk})
        self.assertEqual(key_id, PARENT_ID)
        self.assertEqual(key, class_key)

    def test_view_key_reports_a_missing_view(self):
        with self.assertRaises(kcwrite.KeychainWriteError):
            kcwrite.view_key({"currentkey": []}, {})


class FieldValueTests(unittest.TestCase):
    def test_value_types(self):
        self.assertEqual(decode_fields(ckks.build_field_value(b"x"))[1][0],
                         ckks.VALUE_TYPE_BYTES)
        self.assertEqual(decode_fields(ckks.build_field_value("x"))[1][0],
                         ckks.VALUE_TYPE_STRING)
        self.assertEqual(decode_fields(ckks.build_field_value(7))[1][0],
                         ckks.VALUE_TYPE_INT64)
        with self.assertRaises(TypeError):
            ckks.build_field_value(1.5)


if __name__ == "__main__":
    unittest.main()
