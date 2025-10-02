# import required modules
import unittest
from redacto_audit_log_kit.adapter import GrafanaLokiAdapter
from redacto_audit_log_kit.schema import SearchQuery

class TestGrafanaLokiAdapter(unittest.TestCase):
    def setUp(self):
        self.adapter = GrafanaLokiAdapter()
        
    def test_generate_logql_query_labels_only(self):            
        query = SearchQuery(
            organization_uuid="org-123",
            service_name="svc",
            action="create",
            actor_name=None,
            target_name=None,
            crud="c",
        )
        result = self.adapter._generate_logql_query(query)
        # Order: organization_uuid, vrm_vendor_id, service_name, action, actor_name, target_name, crud
        self.assertEqual(result, '{organization_uuid="org-123", service_name="svc", action="create", crud="c"}')

    def test_generate_logql_query_pipeline_only(self):
        query = SearchQuery(
            source_ip="1.2.3.4",
            target_id="tgt-1",
            group_name="admins",
            description="desc"
        )
        result = self.adapter._generate_logql_query(query)
        # Order: source_ip, target_id, target_type, group_id, group_name, description
        self.assertEqual(result, '{} | source_ip="1.2.3.4" | target_id="tgt-1" | group_name="admins" | description="desc"')

    def test_generate_logql_query_labels_and_pipeline(self):
        query = SearchQuery(
            organization_uuid="org-123",
            service_name="svc",
            source_ip="1.2.3.4",
            description="desc"
        )
        result = self.adapter._generate_logql_query(query)
        # Label order: organization_uuid, vrm_vendor_id, service_name, action, actor_name, target_name, crud
        # Pipeline order: source_ip, target_id, target_type, group_id, group_name, description
        self.assertEqual(result, '{organization_uuid="org-123", service_name="svc"} | source_ip="1.2.3.4" | description="desc"')

    def test_generate_logql_query_empty(self):
        query = SearchQuery()
        result = self.adapter._generate_logql_query(query)
        self.assertEqual(result, '{}')

    def test_generate_logql_query_all_fields(self):
        query = SearchQuery(
            organization_uuid="org-123",
            vrm_vendor_id="vendor-1",
            service_name="svc",
            action="update",
            actor_name="alice",
            target_name="bob",
            crud="u",
            source_ip="1.2.3.4",
            target_id="tgt-1",
            target_type="user",
            group_id="grp-1",
            group_name="admins",
            description="desc"
        )
        result = self.adapter._generate_logql_query(query)
        # Label order: organization_uuid, vrm_vendor_id, service_name, action, actor_name, target_name, crud
        # Pipeline order: source_ip, target_id, target_type, group_id, group_name, description
        self.assertEqual(result, '{organization_uuid="org-123", vrm_vendor_id="vendor-1", service_name="svc", action="update", actor_name="alice", target_name="bob", crud="u"} | source_ip="1.2.3.4" | target_id="tgt-1" | target_type="user" | group_id="grp-1" | group_name="admins" | description="desc"')
