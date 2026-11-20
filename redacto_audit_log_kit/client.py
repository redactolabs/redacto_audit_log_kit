# TODO: this will be an interface dictating the adapter classes what to do
from redacto_audit_log_kit.adapter import adapters_from_env


class AuditClient:
    """
    Without an adapter, AUDIT_LOG_BACKEND picks the adapters (see adapters_from_env).
    With two (dual write), an event is defined once by the first, so every store gets
    the same timestamp and signature, then reported to each in order; the first
    failure raises, so the caller's retry sends it to all again and each store drops
    the repeat. Reads go to the first adapter.
    """

    def __init__(self, adapter=None):
        self.adapters = [adapter] if adapter is not None else adapters_from_env()
        self.adapter = self.adapters[0]

    def report_event(self, defined_event_dict):
        result = self.adapter.report_event(defined_event_dict)
        for adapter in self.adapters[1:]:
            adapter.report_event(defined_event_dict)
        return result

    def define_event(self, *args, **kwargs):
        return self.adapter.define_event(*args, **kwargs)

    def get_events(self, *args, **kwargs):
        return self.adapter.get_events(*args, **kwargs)

    def log(self, audit_log_entry):
        if len(self.adapters) == 1:
            return self.adapter.log(audit_log_entry)
        return self.report_event(self.define_event(audit_log_entry))

    def generate_search_query(self, *args, **kwargs):
        return self.adapter.generate_search_query(*args, **kwargs)
