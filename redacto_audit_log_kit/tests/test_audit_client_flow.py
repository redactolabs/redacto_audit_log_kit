import unittest
import datetime
from redacto_audit_log_kit.client import AuditClient
from redacto_audit_log_kit.adapter import GrafanaLokiAdapter
from redacto_audit_log_kit.schema import AuditEvent, SearchQuery

# class DummyAuditEvent:
#     def __init__(self):
#         self.action = "create"
#         self.crud = "c"
#         self.created = int(datetime.datetime.now().timestamp() * 1_000_000_000)
#         self.source_ip = "127.0.0.1"
#         self.actor_name = "Test Actor"
#         self.group_name = "Test Group"
#         self.target_name = "Test Target"
#         self.target_id = "target-1"
#         self.target_type = "resource"
#         self.description = "Test audit log entry"
#         self.organization_uuid = "org-1"
#         self.vrm_vendor_id = "vendor-1"
#         self.service_name = "svc"

class TestAuditClientFlow(unittest.TestCase):
    def setUp(self):
        self.adapter = GrafanaLokiAdapter()
        self.client = AuditClient(self.adapter)  
        self.audit_event = AuditEvent(
            action = "create",
            crud = "c",
            created = int(datetime.datetime.now().timestamp() * 1_000_000_000),
            source_ip = "127.0.0.1",
            actor_name = "Test Actor",
            group_name = "Test Group",
            target_name = "Test Target",
            target_id = "target-1",
            target_type = "resource",
            description = "Test audit log entry",
            organization_uuid = "org-1",
            vrm_vendor_id = "vendor-1",
            service_name = "svc"
        )     
        self.search_query = SearchQuery(
            organization_uuid="org-1",
            vrm_vendor_id="vendor-1",
            service_name="svc",
            action="create",
            crud="c",
            source_ip="127.0.0.1",
            actor_name="Test Actor",
            group_name="Test Group",
            target_name="Test Target",
            target_id="target-1",
            target_type="resource",
            description="Test audit log entry",
            limit=100,
            interval="5m",
            direction="forward"
        )
    
    def test_define_event(self):
        result = self.client.define_event(self.audit_event)
        self.assertIn("timestamp", result)
        self.assertIn("body", result)
        self.assertIn("labels", result)
        self.assertIn("structured_metadata", result)

    def test_report_event(self):
        event_dict = self.adapter.define_event(self.audit_event)
        result = self.client.report_event(event_dict)
        self.assertIn("status", result)
        self.assertIn("status_code", result)
        self.assertIn("message", result)

    def test_log(self):
        result = self.client.log(self.audit_event)
        self.assertIn("status", result)
        self.assertIn("status_code", result)
        self.assertIn("message", result)

    def test_generate_search_query(self):
        result = self.client.generate_search_query(self.search_query)
        self.assertIn("query", result)
        self.assertEqual(result["limit"], 100)
        self.assertEqual(result["interval"], "5m")
        self.assertEqual(result["direction"], "forward")

#     def z(self):
#         # This will likely fail if Loki is not running, but tests the flow
#         try:
#             result = self.client.get_events(self.search_query)
#             self.assertIsInstance(result, dict)
#         except Exception as e:
#             self.assertTrue(isinstance(e, Exception))

# if __name__ == "__main__":
#     unittest.main()
