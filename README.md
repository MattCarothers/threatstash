# Threatstash - sort of like Logstash, but for indicators

## What does this do?
Threatstash acquires cyber threat indicators using input plugins.  It then passes the indicators through a series of filter plugins that enrich the data, look for sightings in your environment, create relationships, and eliminate false positives.  Finally, it outputs the indicators to an analyst, a block list, an API, a tool, or anything else you can interact with using python.

## Why?
Because copying and pasting from an email into a dozen tools sucks.

## Included plugins

### Input
Currently the only input plugin reads from stdin.  Long term this is meant to consume threat feeds from tools such as MISP.  The code uses STIX 2 under the hood, so it should also be trivial to write a STIX input plugin.

### Filters
* Freeform text - extracts IOCs from freeform text.  Refangs defanged indicators.
* MISP warning lists - compares IOCs to the MISP warning lists and either eliminates them or adds a sighting
* FarSight DNSDB - uses the FarSight passive DNS API to derive IP addresses from hostnames
* Netflow Observed Indicator List (OIL) - See https://github.com/mattcarothers/netflow-oil
* Moloch - uses the Moloch API to check for sessions matching a domain name when the IP addresses derived from the domain were sighted in OIL
* Carbon Black Response - uses the CBR API to check for processes matching a hash or communicating with an IP or domain

### Output
Currently the only output plugin writes CSV to stdout.  Long term this is meant to deliver alerts to a SIEM or push block lists to firewalls, end point agents, etc.

## Quickstart
```
git clone https://github.com/mattcarothers/threatstash
cd threatstash
python3 -m venv .
. bin/activate
pip3 install -r requirements.txt
git clone https://github.com/MISP/misp-warninglists
echo '8[.]8[.]8[.]8' | ./threatstash.py -q config.yml
```
## Under the hood
Threatstash uses a [STIX 2 Environment](https://stix2.readthedocs.io/en/latest/guide/environment.html) internally.  Each IOC is a [STIX ObservedData](https://stix2.readthedocs.io/en/latest/api/stix2.v20.sdo.html) object containing a [STIX Observable](https://stix2.readthedocs.io/en/latest/api/stix2.v20.observables.html).  While this complicates the code, it also allows Threatstash to understand relationships between IOCs using [STIX Relationship](https://stix2.readthedocs.io/en/latest/api/stix2.v20.sro.html) objects and sightings using [STIX Sighting](https://stix2.readthedocs.io/en/latest/api/stix2.v20.sro.html) objects.  The threatstash.Event API hides most of the STIX complexity by providing simpler methods and works around issues such as the inability to modify or remove an object once it's been added to the Environment.  Using STIX internally should also make it relatively easy to write input or output plugins that work dircectly with STIX should someone wish to tackle that.

## Writing new filters
To write a new plugin, start with plugins/filter-dummy.py or one of the other examples.

Import the Plugin superclass:
```
import threatstash.plugin
```

Set the plugin's name, type, ioc types, and required parameters.  The plugin will only be run against observables matching the IOC types list.  Valid IOC types are derived from [STIX 2 Observables](http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716217):
* autonomous-system
* domain-name
* email-addr
* ipv4-addr
* ipv6-addr
* url
* md5
* sha1
* sha256
* sha512
* ssdeep
```
__PLUGIN_NAME__ = 'filter-supercool'
__PLUGIN_TYPE__ = 'filter'
__IOC_TYPES__ = [ 'domain-name' ]
__REQUIRED_PARAMETERS__ = [ ]
```

Write your constructor, inheriting from threatstash.plugin.Plugin.
```
class SuperCoolPlugin(threatstash.plugin.Plugin):
    def __init__(self, config = {}):
        super().__init__(__PLUGIN_NAME__, __PLUGIN_TYPE__, __IOC_TYPES__, __REQUIRED_PARAMETERS__, config)
        # Any other initialization you want here.  This will take place once
        # when the pipeline is instantiated.  This is a good place to set
        # default values for configuration.
```

Optionally write an initialization subroutine.  This routine executes each time a plugin is run, so if you have a plugin listed multiple times in your pipeline config, this routine will run each time.
```
    def init(self):
        # Any other initialization you want here.  This will take place every
        # time the plugin runs.
```

Write your event handler.  This subroutine receives a threatstash.Event object, modifies it, and returns it at the end.  Here are some example methods from threatstash.Event:
```
    def run(self, event):
        # observed_url will be a STIX 2 ObservedData object containing a single
        # STIX 2 Observable
        observed_url = event.add_observation("url", "https://github.com", added_by=__PLUGIN_NAME__)

        # observed_ip will be a STIX 2 ObservedData object containing a single
        # STIX 2 Observable
        observed_ip = event.add_observation("ipv4-addr", "192.30.253.113", added_by=__PLUGIN_NAME__)

        # Add a STIX 2 Relationship between the two ObservedData objects.
        # Methods in threatstash.Event that handle ObservedData objects can
        # operate on the object itself or the object's id parameter.
        event.add_relationship(observed_url, observed_ip, "resolves_to")        

        # Iterate through the Observables in this Event.  Return values are
        # threatstash.Observable objects, which merge parts of the STIX 2
        # ObservedData, the STIX 2 Observables within the ObservedData, and
        # other information that might be be contained within the STIX objects.
        for observable in event.observables:
            # self.debug() logs at the DEBUG level, which will go to stderr
            # when threatstash.py runs with the -d flag
            self.debug("Type:", observable.type, "Value:", observable.value)

        # Iterate through relationships
        for related_observable in event.related_observables(observed_url):
            # self.info() logs at the INFO level unless the -q flag is
            # specified.
            self.info(observed_url.value, related_observable.relationship_type,
                related_observable.value)
    return event
```

See threatstash/event.py for more methods that can run on an Event.
