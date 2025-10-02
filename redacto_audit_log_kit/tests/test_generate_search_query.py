import unittest
import datetime
import time
from redacto_audit_log_kit.schema import SearchQuery
from redacto_audit_log_kit.adapter import GrafanaLokiAdapter

class TestGenerateSearchQuery(unittest.TestCase):
    def setUp(self):
        self.adapter = GrafanaLokiAdapter()
        
    def test_basic_query_params(self):
        """Test generating query parameters with basic fields"""
        search_query = SearchQuery(
            actor_id="12345",
            action="login",
            limit=50
        )
        params = self.adapter.generate_search_query(search_query)
        # LogQL label order: organization_uuid, vrm_vendor_id, service_name, action, actor_name, target_name, crud
        # Only 'action' is a label, so expect: '{action="login"}'
        self.assertTrue('query' in params)
        self.assertEqual(params['query'], '{action="login"}')
        self.assertEqual(params['limit'], 50)
        
    def test_time_params_nanoseconds(self):
        """Test with nanosecond timestamps for start/end"""
        now_ns = int(time.time_ns())
        one_hour_ago_ns = now_ns - (3600 * 1_000_000_000)
        
        search_query = SearchQuery(
            actor_id="12345",
            start=one_hour_ago_ns,
            end=now_ns
        )
        params = self.adapter.generate_search_query(search_query)
        
        self.assertEqual(params['start'], one_hour_ago_ns)
        self.assertEqual(params['end'], now_ns)
        
    def test_time_params_seconds(self):
        """Test with second-based timestamps for start/end (auto-conversion)"""
        now = datetime.datetime.now()
        one_hour_ago = now - datetime.timedelta(hours=1)
        
        # Convert datetime to nanoseconds timestamps (Pydantic requires int)
        start_ns = int(one_hour_ago.timestamp() * 1_000_000_000)
        end_ns = int(now.timestamp() * 1_000_000_000)
        
        search_query = SearchQuery(
            actor_id="12345",
            start=start_ns,
            end=end_ns
        )
        params = self.adapter.generate_search_query(search_query)
        
        # Should be converted to nanoseconds by the function
        expected_start = int(one_hour_ago.timestamp() * 1_000_000_000)
        expected_end = int(now.timestamp() * 1_000_000_000)
        self.assertEqual(params['start'], expected_start)
        self.assertEqual(params['end'], expected_end)
        
    def test_time_params_datetime(self):
        """Test with datetime objects for start/end (auto-conversion)"""
        now = datetime.datetime.now()
        one_hour_ago = now - datetime.timedelta(hours=1)
        
        # Convert datetime to nanoseconds timestamps (Pydantic requires int)
        start_ns = int(one_hour_ago.timestamp() * 1_000_000_000)
        end_ns = int(now.timestamp() * 1_000_000_000)
        
        search_query = SearchQuery(
            actor_id="12345",
            start=start_ns,
            end=end_ns
        )
        params = self.adapter.generate_search_query(search_query)
        
        # Check that values are passed through correctly
        self.assertEqual(params['start'], start_ns)
        self.assertEqual(params['end'], end_ns)
    
    def test_string_params(self):
        """Test with string-based parameters like interval and direction"""
        search_query = SearchQuery(
            actor_id="12345",
            interval="5m",
            direction="forward"
        )
        params = self.adapter.generate_search_query(search_query)
        
        self.assertEqual(params['interval'], "5m")
        self.assertEqual(params['direction'], "forward")
    
    def test_no_time_params(self):
        """Test that the function works without time parameters"""
        search_query = SearchQuery(
            actor_id="12345",
            action="login"
        )
        params = self.adapter.generate_search_query(search_query)
        
        # Should only have the query parameter
        self.assertTrue('query' in params)
        self.assertTrue('start' not in params)
        self.assertTrue('end' not in params)
    
    def test_all_params_together(self):
        """Test all parameters together"""
        now_ns = int(time.time_ns())
        one_hour_ago_ns = now_ns - (3600 * 1_000_000_000)
        search_query = SearchQuery(
            actor_id="12345",
            action="login",
            crud="read",
            limit=100,
            start=one_hour_ago_ns,
            end=now_ns,
            interval="5m",
            direction="backward"
        )
        params = self.adapter.generate_search_query(search_query)
        # Only 'action' and 'crud' are labels, so expect: '{action="login", crud="read"}'
        self.assertTrue('query' in params)
        self.assertEqual(params['query'], '{action="login", crud="read"}')
        self.assertEqual(params['limit'], 100)
        self.assertEqual(params['start'], one_hour_ago_ns)
        self.assertEqual(params['end'], now_ns)
        self.assertEqual(params['interval'], "5m")
        self.assertEqual(params['direction'], "backward")

if __name__ == '__main__':
    unittest.main()