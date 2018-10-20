import threatstash.plugin

# Dummy plugin for testing

__PLUGIN_NAME__ = 'filter-dummy'
__PLUGIN_TYPE__ = 'filter'
__IOC_TYPES__ = [ 'domain-name' ]
__REQUIRED_PARAMETERS__ = [ ]

class Dummy(threatstash.plugin.Plugin):
    def __init__(self, config = {}):
        super().__init__(__PLUGIN_NAME__, __PLUGIN_TYPE__, __IOC_TYPES__, __REQUIRED_PARAMETERS__, config)

    def run(self, event):
        for observable in event.observables:
            if observable.type == "domain-name":
                self.debug("Adding relationship: " + observable.value + " resolves_to 1.2.3.4")
                new_observed_data = event.add_observation("ipv4-addr",
                        "1.2.3.4", added_by=__PLUGIN_NAME__)
                event.add_relationship(observable.id, new_observed_data,
                        "resolves_to")
        return event
