import os
import re
import time
import unittest
import uuid

from pydantic import ValidationError

from redacto_audit_log_kit.adapter import GrafanaLokiAdapter
from redacto_audit_log_kit.schema import (
    MAX_ATTRIBUTES,
    AuditEvent,
    SearchQuery,
    new_event_id,
)
from redacto_audit_log_kit.signing import verify_event_signature

SIGNING_KEY = "test-secret-key"
ORG = "4eb7c2a0-1d9f-4a3b-8c2e-7f0a1b2c3d4e"
WORKSPACE = "91d2f8b1-6c0a-4e2d-9b3f-5a1c2d3e4f60"


def full_event(**overrides):
    fields = dict(
        organization_uuid=ORG,
        workspace_uuid=WORKSPACE,
        vrm_vendor_id="unknown",
        service_name="consent",
        action="accessed",
        crud="r",
        source_ip="203.0.113.42",
        actor_name="dpo@example.com",
        actor_uuid="0f6c2a51-6a52-4d0b-9f1e-2b9c7d3e8a10",
        resource_name="Consent history",
        resource_uuid="01a0d219-50b2-7c6e-b9bd-e9098d74a681",
        resource_type="user_consent",
        description="dpo@example.com accessed consent history log_category=grievance_rights",
        created=1759000000123456789,
    )
    fields.update(overrides)
    return AuditEvent(**fields)


def minimal_event():
    return AuditEvent(
        organization_uuid=ORG,
        service_name="vendor",
        action="created",
        crud="c",
        description="created vendor",
        created=1759000000000000000,
    )


def parse_logql(query):
    selector, _, pipeline = query.partition("}")
    labels = set(re.findall(r'(\w+)="([^"]*)"', selector))
    filters = set(re.findall(r'(\w+)="([^"]*)"', pipeline))
    return labels, filters


class TestExistingOutputUnchanged(unittest.TestCase):
    def setUp(self):
        os.environ["AUDIT_LOG_SIGNING_KEY"] = SIGNING_KEY
        self.adapter = GrafanaLokiAdapter()

    def test_full_event_matches_pre_change_output(self):
        self.assertEqual(
            self.adapter.define_event(full_event()),
            {
                "timestamp": 1759000000123456789,
                "body": "dpo@example.com accessed consent history log_category=grievance_rights",
                "labels": {
                    "organization_uuid": ORG,
                    "workspace_uuid": WORKSPACE,
                    "vrm_vendor_id": "unknown",
                    "service_name": "consent",
                    "kb_id": None,
                },
                "structured_metadata": {
                    "action": "accessed",
                    "crud": "r",
                    "source_ip": "203.0.113.42",
                    "actor_name": "dpo@example.com",
                    "actor_uuid": "0f6c2a51-6a52-4d0b-9f1e-2b9c7d3e8a10",
                    "resource_name": "Consent history",
                    "resource_uuid": "01a0d219-50b2-7c6e-b9bd-e9098d74a681",
                    "resource_type": "user_consent",
                    "event_signature": "644ddb3d560049f55d12183eafa4662c6995c8a5a80201b3f79239d58d9b3bbf",
                },
            },
        )

    def test_minimal_event_matches_pre_change_output(self):
        self.assertEqual(
            self.adapter.define_event(minimal_event()),
            {
                "timestamp": 1759000000000000000,
                "body": "created vendor",
                "labels": {
                    "organization_uuid": ORG,
                    "workspace_uuid": None,
                    "vrm_vendor_id": None,
                    "service_name": "vendor",
                    "kb_id": None,
                },
                "structured_metadata": {
                    "action": "created",
                    "crud": "c",
                    "event_signature": "dfde9c20c9eec197b0269bea24c1c320a6f9640ba24c9e8f18d0e4c3c83f482d",
                },
            },
        )

    def test_search_query_without_new_fields_matches_pre_change_output(self):
        params = self.adapter.generate_search_query(
            SearchQuery(
                organization_uuid="o",
                workspace_uuid="w",
                service_name="consent",
                vrm_vendor_id="unknown",
                start=1,
                end=2,
                limit=11,
            )
        )
        labels, filters = parse_logql(params.pop("query"))
        self.assertEqual(
            labels,
            {
                ("organization_uuid", "o"),
                ("workspace_uuid", "w"),
                ("service_name", "consent"),
                ("vrm_vendor_id", "unknown"),
            },
        )
        self.assertEqual(filters, set())
        self.assertEqual(
            params, {"start": 1000000000, "end": 2000000000, "limit": 11}
        )


class TestLogCategory(unittest.TestCase):
    def setUp(self):
        os.environ["AUDIT_LOG_SIGNING_KEY"] = SIGNING_KEY
        self.adapter = GrafanaLokiAdapter()

    def test_log_category_is_a_label_when_set(self):
        event = self.adapter.define_event(full_event(log_category="grievance_rights"))
        self.assertEqual(event["labels"]["log_category"], "grievance_rights")
        self.assertNotIn("log_category", event["structured_metadata"])

    def test_log_category_absent_adds_no_label(self):
        event = self.adapter.define_event(full_event())
        self.assertNotIn("log_category", event["labels"])
        self.assertNotIn("log_category", event["structured_metadata"])

    def test_unknown_log_category_rejected(self):
        with self.assertRaises(ValidationError):
            full_event(log_category="marketing")

    def test_log_category_is_signed(self):
        event = self.adapter.define_event(full_event(log_category="consent_lifecycle"))
        signature = event["structured_metadata"]["event_signature"]
        self.assertTrue(verify_event_signature(event, signature, SIGNING_KEY))
        event["labels"]["log_category"] = "system_processing"
        self.assertFalse(verify_event_signature(event, signature, SIGNING_KEY))

    def test_search_by_log_category_uses_label_selector(self):
        params = self.adapter.generate_search_query(
            SearchQuery(organization_uuid="o", log_category="consent_lifecycle")
        )
        labels, filters = parse_logql(params["query"])
        self.assertIn(("log_category", "consent_lifecycle"), labels)
        self.assertEqual(filters, set())


class TestAttributes(unittest.TestCase):
    def setUp(self):
        os.environ["AUDIT_LOG_SIGNING_KEY"] = SIGNING_KEY
        self.adapter = GrafanaLokiAdapter()

    def test_attributes_land_in_metadata_with_prefix(self):
        event = self.adapter.define_event(
            full_event(attributes={"result_count": "326", "identifier_field": "org_user_id"})
        )
        metadata = event["structured_metadata"]
        self.assertEqual(metadata["attr_result_count"], "326")
        self.assertEqual(metadata["attr_identifier_field"], "org_user_id")
        self.assertNotIn("attributes", metadata)
        self.assertNotIn("result_count", metadata)

    def test_attribute_cannot_overwrite_core_field(self):
        event = self.adapter.define_event(
            full_event(attributes={"action": "deleted", "actor_uuid": "spoofed"})
        )
        metadata = event["structured_metadata"]
        self.assertEqual(metadata["action"], "accessed")
        self.assertEqual(metadata["actor_uuid"], "0f6c2a51-6a52-4d0b-9f1e-2b9c7d3e8a10")
        self.assertEqual(metadata["attr_action"], "deleted")

    def test_attributes_do_not_change_body(self):
        event = self.adapter.define_event(
            full_event(description="Accessed consent history", attributes={"result_count": "3"})
        )
        self.assertEqual(event["body"], "Accessed consent history")

    def test_attributes_are_signed(self):
        event = self.adapter.define_event(full_event(attributes={"result_count": "3"}))
        signature = event["structured_metadata"]["event_signature"]
        self.assertTrue(verify_event_signature(event, signature, SIGNING_KEY))
        event["structured_metadata"]["attr_result_count"] = "300"
        self.assertFalse(verify_event_signature(event, signature, SIGNING_KEY))

    def test_empty_attributes_add_nothing(self):
        self.assertEqual(
            self.adapter.define_event(full_event(attributes={})),
            self.adapter.define_event(full_event()),
        )

    def test_invalid_attribute_keys_rejected(self):
        for key in ["Result", "result.count", "1st", "", "has-dash", "a" * 65]:
            with self.subTest(key=key), self.assertRaises(ValidationError):
                full_event(attributes={key: "x"})

    def test_attribute_key_at_length_limit_accepted(self):
        full_event(attributes={"a" * 64: "x"})

    def test_non_string_attribute_value_rejected(self):
        with self.assertRaises(ValidationError):
            full_event(attributes={"result_count": 326})

    def test_attribute_count_capped(self):
        full_event(attributes={f"k{i}": "v" for i in range(MAX_ATTRIBUTES)})
        with self.assertRaises(ValidationError):
            full_event(attributes={f"k{i}": "v" for i in range(MAX_ATTRIBUTES + 1)})


class TestEventIdAndActorType(unittest.TestCase):
    def setUp(self):
        os.environ["AUDIT_LOG_SIGNING_KEY"] = SIGNING_KEY
        self.adapter = GrafanaLokiAdapter()

    def test_event_id_and_actor_type_land_in_metadata(self):
        event_id = new_event_id()
        event = self.adapter.define_event(full_event(event_id=event_id, actor_type="human_user"))
        self.assertEqual(event["structured_metadata"]["event_id"], event_id)
        self.assertEqual(event["structured_metadata"]["actor_type"], "human_user")
        self.assertNotIn("event_id", event["labels"])
        self.assertNotIn("actor_type", event["labels"])

    def test_invalid_event_id_rejected(self):
        for value in ["not-a-uuid", "0190C8E2-7B3A-7C4D-9E1F-2A3B4C5D6E7F", ""]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                full_event(event_id=value)

    def test_unknown_actor_type_rejected(self):
        with self.assertRaises(ValidationError):
            full_event(actor_type="admin")

    def test_search_by_event_id_and_actor_type_uses_pipeline_filters(self):
        params = self.adapter.generate_search_query(
            SearchQuery(
                organization_uuid="o",
                event_id="0190c8e2-7b3a-7c4d-9e1f-2a3b4c5d6e7f",
                actor_type="end_user",
            )
        )
        labels, filters = parse_logql(params["query"])
        self.assertEqual(labels, {("organization_uuid", "o")})
        self.assertEqual(
            filters,
            {
                ("event_id", "0190c8e2-7b3a-7c4d-9e1f-2a3b4c5d6e7f"),
                ("actor_type", "end_user"),
            },
        )


class TestNewEventId(unittest.TestCase):
    def test_is_uuid_version_7(self):
        parsed = uuid.UUID(new_event_id())
        self.assertEqual(parsed.version, 7)
        self.assertEqual(parsed.variant, uuid.RFC_4122)

    def test_encodes_current_unix_millis(self):
        before = time.time_ns() // 1_000_000
        parsed = uuid.UUID(new_event_id())
        after = time.time_ns() // 1_000_000
        self.assertTrue(before <= parsed.int >> 80 <= after)

    def test_accepted_by_audit_event(self):
        self.assertIsNotNone(full_event(event_id=new_event_id()).event_id)

    def test_unique(self):
        self.assertEqual(len({new_event_id() for _ in range(1000)}), 1000)


class TestQueueRoundTrip(unittest.TestCase):
    def setUp(self):
        os.environ["AUDIT_LOG_SIGNING_KEY"] = SIGNING_KEY
        self.adapter = GrafanaLokiAdapter()

    def test_new_fields_survive_model_dump_round_trip(self):
        original = full_event(
            log_category="system_processing",
            event_id=new_event_id(),
            actor_type="service_account",
            attributes={"result_count": "326"},
        )
        rebuilt = AuditEvent(**original.model_dump(exclude_none=True))
        self.assertEqual(rebuilt, original)
        self.assertEqual(
            self.adapter.define_event(rebuilt), self.adapter.define_event(original)
        )

    def test_old_payload_without_new_fields_still_accepted(self):
        payload = full_event().model_dump(exclude_none=True)
        for field in ("log_category", "event_id", "actor_type", "attributes"):
            self.assertNotIn(field, payload)
        self.assertEqual(
            self.adapter.define_event(AuditEvent(**payload)),
            self.adapter.define_event(full_event()),
        )


if __name__ == "__main__":
    unittest.main()
