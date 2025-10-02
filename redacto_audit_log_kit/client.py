#TODO: this will be an interface dictating the adapter classes what to do

class AuditClient:
    def __init__(self, adapter):
        #TODO: select adapter (external audit logs library) based on config or input parameter
        self.adapter = adapter

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
