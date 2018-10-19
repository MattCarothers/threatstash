import json
import logging
import requests

import threatstash.plugin

# Enrich IOCs by looking up passive DNS records

__PLUGIN_NAME__ = 'filter-pdns'
__PLUGIN_TYPE__ = 'filter'
__IOC_TYPES__ = [ 'domain-name' ]
__REQUIRED_PARAMETERS__ = [ ]

class PDNSEnricher(threatstash.plugin.Plugin):
    def __init__(self, config = {}):
        super().__init__(__PLUGIN_NAME__, __PLUGIN_TYPE__, __IOC_TYPES__, __REQUIRED_PARAMETERS__, config)

    def run(self, event):
        # Iterate across all the ObservedData objects
        for observable in event.observables:
            # Look for domain-name observables
            if observable.type == "domain-name":
                self.debug("Looking up " + observable.value)
                # Perform a passive dns query
                for rrset in self.rrset(observable.value):
                    # Iterate across the IPs returned
                    uniq = {}
                    for rdata in rrset['rdata']:
                        # Skip duplicates
                        if rdata in uniq:
                            continue
                        self.debug(observable.value + " resolved_to " + rdata)
                        # Create a new ObservedData.  If one already exists
                        # with this value, it will be returned instead.
                        new_observed_data = event.add_observation(
                                "ipv4-addr", rdata, added_by=__PLUGIN_NAME__
                            )
                        # Add the relationships.
                        event.add_relationship(observable.id, new_observed_data, "resolved_to")
                        event.add_relationship(new_observed_data, observable.id, "resolved_from")
                        uniq[rdata] = True
        return event

    # DNSDB rrset name lookup
    def rrset(self, domain):
        return self.dnsdb_query("lookup/rrset/name/" + domain + "/A")

    # DNSDB rdata ip lookup
    def rdata(self, ip):
        # Replace '/' with '-' in case this is a CIDR block
        ip = ip.replace('/', '-')
        return self.dnsdb_query("lookup/rdata/ip/" + ip)

    def dnsdb_query(self, endpoint):
        url = '/'.join(['https://api.dnsdb.info', endpoint])
        r = requests.get(url, headers = {
                'X-API-Key' : self.config['apikey'],
                'Accept' : 'application/json'
            })
        if r.text.rstrip() == "Error: no results found for query.":
            return []
        else:
            return [ json.loads(line) for line in r.text.rstrip().split('\n') ]
