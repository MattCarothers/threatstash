import time
import re
import redis

import threatstash.plugin

__PLUGIN_NAME__ = 'filter-oil-redis'
__PLUGIN_TYPE__ = 'filter'
__IOC_TYPES__ = [
    'ipv4-addr'
]
__REQUIRED_PARAMETERS__ = [
    'server'
]

class RedisOILFilter(threatstash.plugin.Plugin):
    def __init__(self, config = {}):
        super().__init__(__PLUGIN_NAME__, __PLUGIN_TYPE__, __IOC_TYPES__, __REQUIRED_PARAMETERS__, config)
        # Set default port
        if 'port' not in self.config:
            self.config['port'] = 6379
        if 'password' not in self.config:
            self.config['password'] = None
        if 'namespace' not in self.config:
            self.config['namespace'] = ""

    def run(self, event):
        """
        Check the Observed Indicator List (OIL) for sightings of IOCs
        """
        # Connect to Redis
        r = redis.StrictRedis(
                host=self.config['server'],
                port=self.config['port'],
                password=self.config['password']
            )
        # Iterate across STIX ObservedData objects
        for observable in event.observables:
            if observable.type == 'ipv4-addr':
                # Check OIL
                sighting = self.check(r, observable.value)
                # Add a sighting if we got a result
                if sighting:
                    self.debug("sighted " + observable.value
                            + " in netflow at " + sighting['timestamp'])
                    event.add_sighting(observable.id,
                            last_seen=sighting['timestamp'],
                            sighted_by='oil-netflow')
        return event

    def check(self, r, ip):
        if self.config['namespace']:
            key = ':'.join([self.config['namespace'], ip])
        else:
            key = ip
        value = r.get(key)
        if value:
            # value looks like this:
            #
            # /path/to/nfcapd.201810191600:10.0.0.1:8.8.8.8:12345:53:UDP
            value = value.decode('utf8')
            capfile, srcip, dstip, srcport, dstport, proto = value.split(':')
            m = re.search(r'(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})(?P<minute>\d{2})', capfile)
            # Get our UTC offset, accounting for daylight savings time
            is_dst = time.localtime().tm_isdst > 0
            utc_offset = "-%02d:00" % ((time.altzone if is_dst else time.timezone) / 3600)

            timestamp = "%s-%s-%sT%s:%s:00%s" % (
                m.group('year'),
                m.group('month'),
                m.group('day'),
                m.group('hour'),
                m.group('minute'),
                utc_offset
            )
            return {
                'srcip'     : srcip,
                'dstip'     : dstip,
                'srcport'   : srcport,
                'dstport'   : dstport,
                'proto'     : proto,
                'timestamp' : timestamp
            }
        else:
            return None
