import threatstash.plugin

# Plugin to query the Carbon Black Response API
#
# API credentials go in a file named credentials.response located in
# /etc/carbonblack, $HOME/.carbonblack, or $PWD/.carbonblack
#
# See https://developer.carbonblack.com/reference/enterprise-response/authentication/
# for information on generating an API key and https://cbapi.readthedocs.io/en/latest/
# for instructions on how to format the file.

__PLUGIN_NAME__ = 'filter-carbon-black-response'
__PLUGIN_TYPE__ = 'filter'
__IOC_TYPES__ = [ 'domain-name', 'ipv4-addr', 'md5', 'sha256' ]
__REQUIRED_PARAMETERS__ = [ ]

import cbapi.response as cb
import cbapi.errors

class CBRFilter(threatstash.plugin.Plugin):
    def __init__(self, config = {}):
        super().__init__(__PLUGIN_NAME__, __PLUGIN_TYPE__, __IOC_TYPES__, __REQUIRED_PARAMETERS__, config)
        self.cbr = cb.CbResponseAPI()

    def run(self, event):
        for observable in event.observables:
            # Observable is an IP?
            if observable.type == 'ipv4-addr' or observable.type == 'domain-name':
                # Issue a CB process query
                query = 'ipaddr:' if observable.type == 'ipv4-addr' else 'domain:'
                query = query + observable.value
                processes = self.cbr.select(cb.Process).where(query)
                count = len(processes)
                if count > 0:
                    last_seen = processes.first().last_update
                    event.add_sighting(
                        observable.id,
                        last_seen=last_seen,
                        sighted_by='cbr',
                        # The webui link defaults to 0 rows, so we have to
                        # specify a number here in order to see results in a
                        # browser
                        refs=['cbr-url', processes.webui_link + '&rows=10'],
                        count=count
                    )
                    self.debug("sighted", observable.value, "at",
                            str(last_seen))
            else:
                # This observable is a file hash
                try:
                    binary = self.cbr.select(cb.Binary, observable.value)
                    event.add_sighting(
                        observable.id,
                        last_seen=binary.last_seen,
                        sighted_by='cbr',
                        refs=['cbr-url', binary.webui_link]
                    )
                    self.debug("sighted", observable.value, "at",
                            binary.last_seen)
                except cbapi.errors.ObjectNotFoundError as e:
                    self.debug(observable.value, "not found")
                    continue
                except Exception as e:
                    self.debug(
                        "Unable to retrieve binary information from CBR"
                    )
                    self.debug(repr(e))
                    continue

        return event
