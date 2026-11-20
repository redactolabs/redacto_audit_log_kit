# TODO: this will be an interface dictating the adapter classes what to do
from redacto_audit_log_kit.adapter import adapters_from_env, reader_from_env


class AuditClient:
    """
    Without an adapter, AUDIT_LOG_BACKEND picks the adapters (see adapters_from_env)
    and AUDIT_LOG_READ_FROM the one reads go to (see reader_from_env).

    With more than one (dual write), every store is treated the same: the event is
    defined once, so all of them get the same timestamp and signature, and is sent to
    each of them even when another fails. If any failed, the first error is raised
    (with the others as notes), so the caller's retry sends it to all again and each
    store drops the repeat.

    With an explicit adapter, both reads and writes go to it.
    """

    def __init__(self, adapter=None):
        if adapter is not None:
            self.adapters = [adapter]
            self.reader = adapter
            return
        self.adapters = adapters_from_env()
        self.reader = reader_from_env(self.adapters)

    def report_event(self, defined_event_dict):
        results, errors = [], []
        for adapter in self.adapters:
            try:
                results.append(adapter.report_event(defined_event_dict))
            except Exception as e:
                errors.append(e)
        if errors:
            for other in errors[1:]:
                errors[0].add_note(f"also failed: {other}")
            raise errors[0]
        if len(results) == 1:
            return results[0]
        return {
            "status": "success",
            "message": "Event reported to every store",
            "stores": {type(a).__name__: r for a, r in zip(self.adapters, results)},
        }

    def define_event(self, *args, **kwargs):
        return self.reader.define_event(*args, **kwargs)

    def get_events(self, *args, **kwargs):
        return self.reader.get_events(*args, **kwargs)

    def log(self, audit_log_entry):
        if len(self.adapters) == 1:
            return self.adapters[0].log(audit_log_entry)
        return self.report_event(self.define_event(audit_log_entry))

    def generate_search_query(self, *args, **kwargs):
        return self.reader.generate_search_query(*args, **kwargs)
