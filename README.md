# Threatstash - sort of like Logstash, but for indicators

## What does this do?
Threatstash acquires cyber threat indicators using input plugins.  It then passes the indicators through a series of filter plugins that enrich the data, look for sightings in your environment, create relationships, and eliminate false positives.  Finally, it outputs the indicators to an analyst, a block list, an API, a tool, or anything else you can interact with using python.

## Why?
Because copying and pasting from an email into a dozen tools sucks.

## Included plugins

### Input
Currently the only input plugin reads from stdin.  Long term this is meant to consume threat feeds from tools such as MISP.

### Filters
* Freeform text - extracts IOCs from freeform text.  Refangs defanged indicators.
* MISP warning lists - compares IOCs to the MISP warning lists and either eliminates them or adds a sighting
* FarSight DNSDB - uses the FarSight passive DNS API to derive IP addresses from hostnames
* Netflow Observed Indicator List (OIL) - See https://github.com/mattcarothers/netflow-oil
* Moloch - uses the Moloch API to check for sessions matching a domain name when the IP addresses derived from the domain were sighted in OIL

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
