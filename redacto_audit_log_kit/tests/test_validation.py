import unittest
from pydantic import ValidationError
from redacto_audit_log_kit.schema import (
    SearchQuery,
    MAX_LIMIT,
    MIN_LIMIT,
    MAX_TIMESTAMP_NS,
    MIN_TIMESTAMP_NS,
)
from redacto_audit_log_kit.adapter import GrafanaLokiAdapter
from redacto_audit_log_kit.exceptions import AuditKitInvalidDataError


class TestSearchQueryValidation(unittest.TestCase):
    """Test Pydantic validation for SearchQuery parameters."""

    def test_valid_limit_default(self):
        """Test default limit value."""
        q = SearchQuery()
        self.assertEqual(q.limit, 100)

    def test_valid_limit_custom(self):
        """Test custom valid limit values."""
        q = SearchQuery(limit=500)
        self.assertEqual(q.limit, 500)

        q = SearchQuery(limit=MAX_LIMIT)
        self.assertEqual(q.limit, MAX_LIMIT)

        q = SearchQuery(limit=MIN_LIMIT)
        self.assertEqual(q.limit, MIN_LIMIT)

    def test_limit_exceeds_max(self):
        """Test that limit exceeding MAX_LIMIT raises ValidationError."""
        with self.assertRaises(ValidationError):
            SearchQuery(limit=MAX_LIMIT + 1)

    def test_limit_below_min(self):
        """Test that limit below MIN_LIMIT raises ValidationError."""
        with self.assertRaises(ValidationError):
            SearchQuery(limit=0)

        with self.assertRaises(ValidationError):
            SearchQuery(limit=-1)

    def test_limit_overflow_value(self):
        """Test that overflow limit values raise ValidationError."""
        with self.assertRaises(ValidationError):
            SearchQuery(limit=100000000000000000000000000001)

    def test_valid_timestamp(self):
        """Test valid nanosecond timestamps."""
        valid_ts = 1714500000000000000  # ~2024 in nanoseconds
        q = SearchQuery(start=valid_ts, end=valid_ts + 1000000000)
        self.assertEqual(q.start, valid_ts)
        self.assertEqual(q.end, valid_ts + 1000000000)

    def test_timestamp_at_max(self):
        """Test timestamp at maximum allowed value."""
        q = SearchQuery(start=MAX_TIMESTAMP_NS)
        self.assertEqual(q.start, MAX_TIMESTAMP_NS)

    def test_timestamp_exceeds_max(self):
        """Test that timestamp exceeding MAX_TIMESTAMP_NS raises ValidationError."""
        with self.assertRaises(ValidationError):
            SearchQuery(start=MAX_TIMESTAMP_NS + 1)

        with self.assertRaises(ValidationError):
            SearchQuery(end=MAX_TIMESTAMP_NS + 1)

    def test_timestamp_overflow_value(self):
        """Test that overflow timestamp values raise ValidationError."""
        with self.assertRaises(ValidationError):
            SearchQuery(start=1771909188952000000000000000)

    def test_negative_timestamp(self):
        """Test that negative timestamps raise ValidationError."""
        with self.assertRaises(ValidationError):
            SearchQuery(start=-1)

    def test_combined_valid_params(self):
        """Test valid combination of all params."""
        q = SearchQuery(
            limit=500,
            start=1714500000000000000,
            end=1714500001000000000,
            actor_uuid="test-actor",
        )
        self.assertEqual(q.limit, 500)
        self.assertEqual(q.start, 1714500000000000000)
        self.assertEqual(q.end, 1714500001000000000)


class TestAdapterRuntimeValidation(unittest.TestCase):
    """Test runtime validation in GrafanaLokiAdapter."""

    def setUp(self):
        self.adapter = GrafanaLokiAdapter()

    def test_adapter_validates_limit_in_generate_search_query(self):
        """Test that adapter validates limit in generate_search_query."""
        # Valid limit should work
        q = SearchQuery(limit=500)
        params = self.adapter.generate_search_query(q)
        self.assertEqual(params["limit"], 500)

    def test_adapter_validates_timestamp_in_generate_search_query(self):
        """Test that adapter validates timestamps in generate_search_query."""
        valid_ts = 1714500000000000000
        q = SearchQuery(start=valid_ts, end=valid_ts + 1000000000)
        params = self.adapter.generate_search_query(q)
        self.assertEqual(params["start"], valid_ts)
        self.assertEqual(params["end"], valid_ts + 1000000000)
