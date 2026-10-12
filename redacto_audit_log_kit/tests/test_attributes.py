import os
import unittest

from pydantic import ValidationError

from redacto_audit_log_kit.adapter import GrafanaLokiAdapter
from redacto_audit_log_kit.attributes import (
    DROPPED_ATTRIBUTES_KEY,
    MAX_DROPPED_REPORT_BYTES,
    attribute_key,
    attribute_value,
    build_attributes,
)
from redacto_audit_log_kit.schema import (
    MAX_ATTRIBUTE_VALUE_BYTES,
    MAX_ATTRIBUTES,
    MAX_ATTRIBUTES_BYTES,
    AuditEvent,
    derive_event_id,
)


def attributes_bytes(attributes):
    return sum(len("attr_") + len(k) + len(v.encode()) for k, v in attributes.items())


class BuildAttributesTests(unittest.TestCase):
    def test_success_values_are_stringified_and_none_is_dropped(self):
        self.assertEqual(
            build_attributes(
                {
                    "result_count": 326,
                    "cascade": True,
                    "declined": False,
                    "ratio": 1.0,
                    "languages": ["en", "hi"],
                    "summary": {"granted": 2, "denied": 1},
                    "case_uuid": None,
                    "case_id": "",
                }
            ),
            {
                "result_count": "326",
                "cascade": "true",
                "declined": "false",
                "ratio": "1.0",
                "languages": '["en","hi"]',
                "summary": '{"denied":1,"granted":2}',
                "case_id": "",
            },
        )

    def test_success_keys_are_normalized(self):
        self.assertEqual(attribute_key("consent.notice_uuid"), "consent_notice_uuid")
        self.assertEqual(attribute_key("Result.Count"), "result_count")
        self.assertEqual(attribute_key("1st"), "k_1st")
        self.assertEqual(attribute_key("has-dash"), "has_dash")
        self.assertEqual(attribute_key("x" * 80), "x" * 64)

    def test_success_colliding_keys_resolve_the_same_way_in_any_order(self):
        forward = build_attributes({"a.b": "first", "a_b": "second"})
        backward = build_attributes({"a_b": "second", "a.b": "first"})

        self.assertEqual(forward, {"a_b": "second"})
        self.assertEqual(backward, forward)

    def test_success_non_ascii_json_is_kept_readable(self):
        self.assertEqual(attribute_value({"name": "गोपनीयता"}), '{"name":"गोपनीयता"}')

    def test_failure_oversized_value_is_truncated_with_its_original_size(self):
        value = build_attributes({"note": "a" * 200_000})["note"]

        self.assertLessEqual(len(value.encode()), MAX_ATTRIBUTE_VALUE_BYTES)
        self.assertTrue(value.endswith("...[truncated 200000 bytes]"))

    def test_failure_truncation_never_splits_a_multibyte_character(self):
        value = build_attributes({"note": "a" + "गोपनीयता" * 2_000})["note"]

        self.assertNotIn("�", value)
        value.encode().decode()

    def test_failure_attributes_beyond_the_budget_are_dropped_and_listed(self):
        extra = {f"blob_{i:02d}": "x" * 8_000 for i in range(20)}
        attributes = build_attributes(extra)

        kept = sorted(k for k in attributes if k.startswith("blob_"))
        dropped = attributes[DROPPED_ATTRIBUTES_KEY].split(",")
        self.assertTrue(0 < len(kept) < len(extra))
        self.assertEqual(sorted(kept + dropped), sorted(extra))
        self.assertLessEqual(attributes_bytes(attributes), MAX_ATTRIBUTES_BYTES)

    def test_failure_long_dropped_list_falls_back_to_a_count(self):
        extra = {f"{i:03d}".rjust(64, "k"): "v" for i in range(230)}
        attributes = build_attributes(extra)

        report = attributes[DROPPED_ATTRIBUTES_KEY]
        self.assertEqual(report, f"{len(extra) - (len(attributes) - 1)} attributes")
        self.assertLessEqual(len(report.encode()), MAX_DROPPED_REPORT_BYTES)

    def test_failure_attribute_count_stays_within_the_limit(self):
        attributes = build_attributes({f"k{i:03d}": "v" for i in range(150)})

        self.assertLessEqual(len(attributes), MAX_ATTRIBUTES)

    def test_success_output_is_always_accepted_by_audit_event(self):
        inputs = [
            {f"blob_{i:02d}": "x" * 9_000 for i in range(20)},
            {f"{i:03d}".rjust(64, "k"): "v" for i in range(230)},
            {"note": "गोपनीयता" * 5_000, "Weird.Key-1": [1, 2], "empty": ""},
        ]
        for extra in inputs:
            with self.subTest(keys=len(extra)):
                AuditEvent(attributes=build_attributes(extra))


class AttributeCapValidationTests(unittest.TestCase):
    def test_failure_value_over_the_cap_is_rejected(self):
        with self.assertRaises(ValidationError):
            AuditEvent(attributes={"note": "x" * (MAX_ATTRIBUTE_VALUE_BYTES + 1)})

    def test_success_value_at_the_cap_is_accepted(self):
        AuditEvent(attributes={"note": "x" * MAX_ATTRIBUTE_VALUE_BYTES})

    def test_failure_total_over_the_cap_is_rejected(self):
        with self.assertRaises(ValidationError):
            AuditEvent(attributes={f"k{i:02d}": "x" * 8_000 for i in range(7)})

    def test_success_empty_value_is_accepted(self):
        os.environ["AUDIT_LOG_SIGNING_KEY"] = "test-secret-key"
        event = GrafanaLokiAdapter().define_event(
            AuditEvent(organization_uuid="o", attributes={"case_id": ""})
        )

        self.assertEqual(event["structured_metadata"]["attr_case_id"], "")


class DeriveEventIdTests(unittest.TestCase):
    def test_success_matches_the_go_ledger_derivation(self):
        self.assertEqual(
            derive_event_id("consent.event:0190c8e2-7b3a-7c4d-9e1f-2a3b4c5d6e7f"),
            "6f2601a2-cbb1-5751-9122-46e0a2b5f371",
        )

    def test_success_is_deterministic_and_accepted_as_an_event_id(self):
        first = derive_event_id("consent.event:a")

        self.assertEqual(first, derive_event_id("consent.event:a"))
        self.assertNotEqual(first, derive_event_id("consent.event:b"))
        AuditEvent(event_id=first)


if __name__ == "__main__":
    unittest.main()
