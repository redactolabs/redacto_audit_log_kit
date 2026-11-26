# TODO: this will be an interface dictating the adapter classes what to do
from redacto_audit_log_kit.events import define_event, signing_key_from_env
from redacto_audit_log_kit.exceptions import (
    AuditKitConnectionError,
    AuditKitError,
    AuditKitExternalServiceError,
)
from redacto_audit_log_kit.factory import adapters_from_env, reader_from_env


def is_retryable(error):
    if isinstance(error, AuditKitConnectionError):
        return True
    return isinstance(error, AuditKitExternalServiceError) and not error.permanent


class AuditClient:
    """
    Without an adapter, AUDIT_LOG_BACKEND picks the adapters (see adapters_from_env)
    and AUDIT_LOG_READ_FROM the one reads go to (see reader_from_env).

    With more than one (dual write), every store is treated the same: the event is
    defined once, so all of them get the same timestamp and signature, and is sent to
    each of them even when another fails. If any failed, one error is raised (with
    the others as notes), so the caller's retry sends it to all again and each store
    drops the repeat. A retryable error is raised ahead of a permanent one, so a
    store that can still take the event is not given up on.

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
            except AuditKitError as e:
                errors.append(e)
        if errors:
            errors.sort(key=lambda e: not is_retryable(e))
            for other in errors[1:]:
                errors[0].add_note(f"also failed: {other}")
            raise errors[0]
        if len(results) == 1:
            return results[0]
        return {
            "status": "success",
            "message": "Event reported to every store",
            "stores": {a.name: r for a, r in zip(self.adapters, results)},
        }

    def define_event(self, audit_log_entry):
        return define_event(audit_log_entry, signing_key_from_env())

    def get_events(self, *args, **kwargs):
        return self.reader.get_events(*args, **kwargs)

    def get_page(self, search_query):
        return self.reader.get_page(search_query)

    def log(self, audit_log_entry):
        return self.report_event(self.define_event(audit_log_entry))

    def generate_search_query(self, *args, **kwargs):
        return self.reader.generate_search_query(*args, **kwargs)
