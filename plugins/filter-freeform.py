import re
import validators

from tld import get_tld, get_fld

import threatstash.plugin
import threatstash.util

# Extract IOCs from freeform text

__PLUGIN_NAME__ = 'filter-freeform'
__PLUGIN_TYPE__ = 'filter'
__IOC_TYPES__ = [ 'context' ]
__REQUIRED_PARAMETERS__ = [ ]

class IOCExtractor(threatstash.plugin.Plugin):
    def __init__(self, config = {}):
        super().__init__(__PLUGIN_NAME__, __PLUGIN_TYPE__, __IOC_TYPES__, __REQUIRED_PARAMETERS__, config)

    def run(self, event):
        # Some dicts to avoid duplication of IOCs
        ips       = {}
        urls      = {}
        hostnames = {}
        hashes    = {}

        # Merge all the 'text' type IOCs into one blob along with the event's
        # context field before processing them.
        text = str(event.context)
#        for observable in event.observables:
#            if observable.type == "text":
#                text = text + "\n" + observable.value

        for line in text.split("\n"):
            self.debug("Line: " + line)
            # Strip leading/trailing whitespace
            line = line.strip()

            #####################
            # Refang indicators #
            #####################
            line = threatstash.util.refang(line)

            ######################
            # Extract indicators #
            ######################

            # Extract IPs
            for ip in re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
                ips[ip] = True
                self.debug("IP: " + ip)

            # Extract URLs
            if re.search(r'https?://', line):
                # http://blah.com/blah
                for url in re.findall(r'https?://\S+', line):
                    urls[url] = True
                    self.debug("URL: " + url)
            else:
                # blah.com/blah
                for url in re.findall(r'[a-zA-Z0-9-\.]+\.[a-zA-Z]{2,}/\S+', line):
                    url = 'http://' + url
                    urls[url] = True
                    self.debug("URL2: " + url)

            # Extract hostnames
            for hostname in re.findall(r'[a-zA-Z0-9-\.]+\.[a-zA-Z]{2,}', line):
                self.debug("Hostname: " + hostname)
                hostnames[hostname] = True

            # Extract hashes
            # SHA256
            for hash in re.findall(r'\b[a-fA-F0-9]{64}\b', line):
                hashes[hash] = True
            # SHA1
            for hash in re.findall(r'\b[a-fA-F0-9]{40}\b', line):
                hashes[hash] = True
            # MD5
            for hash in re.findall(r'\b[a-fA-F0-9]{32}\b', line):
                hashes[hash] = True

        # Validate and return the data
        iocs = []
        self.debug("IPs: " + str(ips))
        for ip in ips.keys():
            if validators.ipv4(ip):
                self.debug("Appending IP: " + ip)
                event.add_observation("ipv4-addr", ip, added_by=__PLUGIN_NAME__)
            else:
                self.debug("Invalid IP: " + ip)
        
        derived_from = {}
        for url in urls.keys():
            tld = get_tld(url, fail_silently=True)
            fld = get_fld(url, fail_silently=True)
            if not validators.url(url):
            #or not tld or not fld:
                self.debug("Invalid URL: " + url)
                continue
            else:
                observed_url = event.add_observation("url", url, added_by=__PLUGIN_NAME__)
                # Extract hostname from URL
                m = re.search(r'https?://([^/:]+)[/:]', url)
                if m:
                    hostname = m.group(1)
                    hostname = hostname.lower()
                    hostnames[hostname] = True
                    self.debug("Hostname from URL: " + hostname)
                    # Keep track of where this hostname came from so we can add
                    # a Relationship later.
                    derived_from[hostname] = observed_url

        for hostname in hostnames.keys():
            hostname = hostname.lower()
            tld = get_tld(hostname, fail_silently=True, fix_protocol=True)
            fld = get_fld(hostname, fail_silently=True, fix_protocol=True)
            if not validators.domain(hostname) or not tld or not fld:
                self.debug("Invalid Hostname: " + hostname)
                continue
            else:
                observed_hostname = event.add_observation(
                        "domain-name",
                        hostname,
                        added_by=__PLUGIN_NAME__
                    )
                if hostname in derived_from:
                    event.add_relationship(
                            observed_hostname,
                            derived_from[hostname],
                            'derived_from'
                        )

        for hash in hashes.keys():
            if len(hash) == 32:
                event.add_observation("md5", hash, added_by=__PLUGIN_NAME__)
            elif len(hash) == 40:
                event.add_observation("sha1", hash, added_by=__PLUGIN_NAME__)
            elif len(hash) == 64:
                event.add_observation("sha256", hash, added_by=__PLUGIN_NAME__)

        return event
