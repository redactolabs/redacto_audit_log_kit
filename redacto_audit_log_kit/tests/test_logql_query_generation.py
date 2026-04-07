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
            resource_name=None,
            crud="c",
        )
        result = self.adapter._generate_logql_query(query)
        # label_fields and pipeline_filter_fields are sets (unordered)
        # Check that the result contains the expected label selector and pipeline filters
        self.assertIn('organization_uuid="org-123"', result)
        self.assertIn('service_name="svc"', result)
        self.assertIn('action="create"', result)
        self.assertIn('crud="c"', result)
        # Verify structure: labels in braces, pipeline filters after
        self.assertTrue(result.startswith("{"))
        self.assertIn("} |", result)

    def test_generate_logql_query_pipeline_only(self):
        query = SearchQuery(
            source_ip="1.2.3.4",
            resource_uuid="res-1",
            resource_type="user",
            description="desc",
        )
        result = self.adapter._generate_logql_query(query)
        # pipeline_filter_fields are sets (unordered)
        # Check that the result contains the expected pipeline filters
        self.assertTrue(result.startswith("{}"))
        self.assertIn('source_ip="1.2.3.4"', result)
        self.assertIn('resource_uuid="res-1"', result)
        self.assertIn('resource_type="user"', result)
        self.assertIn('description="desc"', result)

    def test_generate_logql_query_labels_and_pipeline(self):
        query = SearchQuery(
            organization_uuid="org-123",
            service_name="svc",
            source_ip="1.2.3.4",
            description="desc",
        )
        result = self.adapter._generate_logql_query(query)
        # label_fields and pipeline_filter_fields are sets (unordered)
        # Check that the result contains expected labels and pipeline filters
        self.assertIn('organization_uuid="org-123"', result)
        self.assertIn('service_name="svc"', result)
        self.assertIn('source_ip="1.2.3.4"', result)
        self.assertIn('description="desc"', result)
        # Verify structure: labels in braces, pipeline filters after
        self.assertTrue(result.startswith("{"))
        self.assertIn("} |", result)

    def test_generate_logql_query_empty(self):
        query = SearchQuery()
        result = self.adapter._generate_logql_query(query)
        self.assertEqual(result, "{}")

    def test_generate_logql_query_all_fields(self):
        query = SearchQuery(
            organization_uuid="org-123",
            vrm_vendor_id="vendor-1",
            service_name="svc",
            kb_id="kb-1",
            action="update",
            actor_name="alice",
            actor_uuid="actor-1",
            resource_name="bob",
            resource_uuid="res-1",
            resource_type="user",
            crud="u",
            source_ip="1.2.3.4",
            description="desc",
        )
        result = self.adapter._generate_logql_query(query)
        # label_fields and pipeline_filter_fields are sets (unordered)
        # Check that the result contains all expected labels
        self.assertIn('organization_uuid="org-123"', result)
        self.assertIn('vrm_vendor_id="vendor-1"', result)
        self.assertIn('service_name="svc"', result)
        self.assertIn('kb_id="kb-1"', result)
        # Check that the result contains all expected pipeline filters
        self.assertIn('action="update"', result)
        self.assertIn('actor_name="alice"', result)
        self.assertIn('actor_uuid="actor-1"', result)
        self.assertIn('resource_name="bob"', result)
        self.assertIn('resource_uuid="res-1"', result)
        self.assertIn('resource_type="user"', result)
        self.assertIn('crud="u"', result)
        self.assertIn('source_ip="1.2.3.4"', result)
        self.assertIn('description="desc"', result)
        # Verify structure: labels in braces, pipeline filters after
        self.assertTrue(result.startswith("{"))
        self.assertIn("} |", result)
