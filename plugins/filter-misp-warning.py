import json
import logging
import os
import SubnetTree
from tld import get_tld, get_fld

import threatstash.plugin

# git clone https://github.com/MISP/misp-warninglists

__PLUGIN_NAME__ = 'filter-misp-warning'
__PLUGIN_TYPE__ = 'filter'
__IOC_TYPES__ = [
    'ipv4-addr',
    'domain-name'
]
__REQUIRED_PARAMETERS__ = [
    'warning_list_dir',
    'warning_lists'
]

class MISPWarning(threatstash.plugin.Plugin):
    def __init__(self, config = {}):
        super().__init__(__PLUGIN_NAME__, __PLUGIN_TYPE__, __IOC_TYPES__, __REQUIRED_PARAMETERS__, config)
        self.lists = []
        if "revoke" not in self.config:
            self.config["revoke"] = False

    def init(self):
        super().init()
        # Load the warning lists.  We don't do this in __init__ because we
        # haven't received our configuration yet.
        for warning_list in self.config["warning_lists"]:
            filename = os.path.join(self.config["warning_list_dir"], "lists", warning_list, "list.json")
            with open(filename) as f:
                data = json.load(f)
                if data["type"] == "cidr":
                    entries = SubnetTree.SubnetTree()
                else:
                    entries = {}
                for entry in data["list"]:
                    entry = entry.lower()
                    entries[entry] = True
                self.lists.append({
                        "name"    : data["name"],
                        "type"    : data["type"],
                        "entries" : entries
                    })
                self.debug("Loaded warning list", data["name"])

    def run(self, event):
        """
        Check IOCs against MISP Warning Lists
        git clone https://github.com/MISP/misp-warninglists
        """
        # Iterate across Observables
        for observable in event.observables:
            for warning_list in self.lists:
                self.debug("Checking", observable.value, "against", warning_list["name"])

                # Only check IPs against CIDR lists.  SubnetTree throws an
                # exception if you test a non-IP against it.
                if warning_list["type"] == "cidr" and observable.type != "ip4-addr" and observable.type != "ip6-addr":
                    continue

                # If we have a domain name, extract its FLD.  E.g. for
                # foo.bar.com, also test bar.com and for foo.bar.co.uk, also
                # check bar.co.uk.
                fld = ""
                if observable.type == "domain-name":
                    # get_fld chokes if you feed it a hostname instead of a URL
                    fld = get_fld("http://" + observable.value, fail_silently=True)
                elif observable.type == "url":
                    fld = get_fld(observable.value, fail_silently=True)

                if observable.value in warning_list["entries"] or fld in warning_list["entries"]:
                    self.debug("Sighted", observable.value, "in", warning_list["name"])
                    event.add_sighting(
                            observable.id,
                            sighted_by="misp-warning",
                            refs=["warning-list", warning_list["name"]]
                        )
                    if self.config["revoke"]:
                        event.revoke(observable.id)
                    # Stop after our first match
                    break
        return event
