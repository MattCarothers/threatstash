import datetime
import dateutil.parser
import json
import logging
import requests
import urllib

import threatstash.plugin

__PLUGIN_NAME__ = 'filter-moloch'
__PLUGIN_TYPE__ = 'filter'
__IOC_TYPES__ = [
    'ipv4-addr'
]
__REQUIRED_PARAMETERS__ = [
    'url',
    'username',
    'password'
]

class MolochAPI(threatstash.plugin.Plugin):
    def __init__(self, config = {}):
        super().__init__(__PLUGIN_NAME__, __PLUGIN_TYPE__, __IOC_TYPES__, __REQUIRED_PARAMETERS__, config)
        # Verify TLS certificate by default
        if 'verify' not in self.config:
            self.config['verify'] = True

    def run(self, event):
        """
        Check the Moloch for sightings of IOCs
        """
        # Iterate across STIX ObservedData objects
        for observable in event.observables:
            if observable.type == 'ipv4-addr':
                # Has this Observable been sighted?
                for sighting in event.sightings_of(observable.id):
                    self.debug(observable.value, "was sighted at", str(sighting.last_seen), "by", sighting.sighted_by)
                    # Check the Relationships for the ObservedData and see if
                    # it was resolved from a domain-name indicator
                    for related_observable in event.related_observables(observable.id):
                        if related_observable.relationship_type == 'resolved_from':
                            self.debug(observable.value, 'resolved_from', related_observable.value)
#                                self.debug(
#                                        "checking Moloch for ip==%s && host==%s at %s" % (
#                                            observable.value,
#                                            related_observable.value,
#                                            str(sighting.last_seen))
#                                        )

                            # Don't query Sightings that are older than our
                            # Moloch retention
                            if 'max_age' in self.config:
                                # Find the time max_age days ago
                                minimum_timestamp = datetime.datetime.now().timestamp() - self.config['max_age'] * 86400
                                sighting_timestamp = dateutil.parser.parse(
                                            str(sighting.last_seen)
                                        ).timestamp()
                                if sighting_timestamp < minimum_timestamp:
                                    self.debug("Sighting timestamp",
                                            str(sighting.last_seen),
                                            "is older than",
                                            str(self.config['max_age']),
                                            "days")
                                    continue

                            # Check Moloch for both the IP and the domain
                            # name it was resolved from
                            expression = "ip==%s && host==%s" % (
                                    observable.value,
                                    related_observable.value
                                )
                            sessions, url = self.moloch_query(
                                    expression,
                                    timestamp=str(sighting.last_seen)
                                )
                            #self.debug("Moloch found", str(sessions['recordsFiltered']), "sessions")
                            if sessions['recordsFiltered'] > 0:
                                # Unix timestamp of the last packet of the first session
                                last_seen = sessions['data'][0]['lastPacket'] / 1000
                                # Convert to ISO8601
                                last_seen = datetime.datetime.fromtimestamp(
                                        last_seen,
                                        dateutil.tz.tzutc()
                                    ).isoformat()
                                session_id = sessions['data'][0]['id']
                                event.add_sighting(
                                        related_observable.id,
                                        last_seen=last_seen,
                                        sighted_by='moloch',
                                        #refs=['moloch-url', url, 'moloch-session', session_id]
                                        refs=['moloch-url', url]
                                    )
                                self.debug("sighted", observable.value, "+",
                                        related_observable.value, "at",
                                        last_seen)
        return event

    def moloch_query(self, expression, timestamp):
        # Convert the timestamp to the local timezone.
        timestamp = dateutil.parser.parse(timestamp).astimezone(dateutil.tz.tzlocal())
        # Start time is 00:00:00 of the day of the sighting
        start_time = timestamp.strftime('%Y-%m-%dT00:00:00%z')
        # Stop time is 23:59:59 of the day of the sighting
        stop_time = timestamp.strftime('%Y-%m-%dT23:59:59%z')
        # Convert the times into unix timestamps. Note: python 3.3+ required
        # for the timestamp() method.
        start_time = int(dateutil.parser.parse(start_time).timestamp())
        stop_time  = int(dateutil.parser.parse(stop_time).timestamp())

        # Do we have a default expression?
        if 'base_query' in self.config:
            expression = "(%s) && (%s)" % (self.config['base_query'], expression)
            self.debug("Expression is now", expression)

        # Build our query URL
        query_string = urllib.parse.urlencode({
                'startTime'  : start_time,
                'stopTime'   : stop_time,
                'expression' : expression
            })
        api_url   = "%s/sessions.json?%s&length=1" % (self.config['url'], query_string)
        human_url = "%s/sessions?%s" % (self.config['url'], query_string)
        # Fetch sessions from Moloch
        r = requests.get(
                api_url,
                auth=(self.config['username'], self.config['password']),
                verify=self.config['verify']
            )
        if r.status_code != 200:
            raise requests.RequestException("Bad status: " + str(r.status_code) + "\n" + r.text)
        if r.text[:5] == "ERROR":
            raise requests.RequestException("Moloch error: " + r.text)
        return r.json(), human_url
