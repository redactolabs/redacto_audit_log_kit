# TODO: this will be an interface dictating the adapter classes what to do
from redacto_audit_log_kit.adapter import adapter_from_env


class AuditClient:
    def __init__(self, adapter=None):
        # Without an adapter, AUDIT_LOG_BACKEND picks one (see adapter_from_env).
        self.adapter = adapter if adapter is not None else adapter_from_env()

    def report_event(self, *args, **kwargs):
        return self.adapter.report_event(*args, **kwargs)

    def define_event(self, *args, **kwargs):
        return self.adapter.define_event(*args, **kwargs)

    def get_events(self, *args, **kwargs):
        return self.adapter.get_events(*args, **kwargs)

    def log(self, *args, **kwargs):
        return self.adapter.log(*args, **kwargs)

    def generate_search_query(self, *args, **kwargs):
        return self.adapter.generate_search_query(*args, **kwargs)
