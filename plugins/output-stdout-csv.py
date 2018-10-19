import time
import threatstash.plugin

__PLUGIN_NAME__ = 'output-stdout-csv'
__PLUGIN_TYPE__ = 'output'
__IOC_TYPES__ = [ ]
__REQUIRED_PARAMETERS__ = [ ]

class StdoutOutputCSV(threatstash.plugin.Plugin):
    def __init__(self, config = {}):
        super().__init__(__PLUGIN_NAME__, __PLUGIN_TYPE__, __IOC_TYPES__, __REQUIRED_PARAMETERS__, config)

    def run(self, event):
        """
        Output an event to stdout by dumping it as csv
        """
        print(','.join([
                    "Type", "Value", "Added By", "Relationship",
                    "Related Type", "Related Value", "Related Added By",
                    "Sighted", "Sighted By", "Last Seen", "Ref Type", "Ref Value"
                ])
            )
        # Iterate across STIX ObservedData objects
        for observable in event.observables:
            #start = time.time()
            sighted = event.sighted(observable.id)
            #elapsed = time.time() - start
            #self.debug("event.sighted(observable.id) took", str(elapsed), "seconds for", observable.value)
            # Create a unique list of tools that sighted the ObservableData
            sighters = {}
            last_seen = ""
            external_reference = ""
            #start = time.time()
            for sighting in event.sightings_of(observable.id):
                # Record the name of our sighted_by
                sighters[sighting.sighted_by] = True
                # Record the most recent last_seen date from all sightings
                if str(sighting.last_seen) > last_seen:
                    last_seen = str(sighting.last_seen)
                # If this Sighting has external references, record the last
                # one.
                #
                # TODO: figure out how to represent an observable with multiple
                #       Sightings, each of which has external references. 
                # TODO: figure out how to represent a Sighting with multiple
                #       external references 
                if hasattr(sighting, 'external_references'):
                    for ref in sighting.external_references:
                        external_reference = ','.join([
                                ref.source_name,
                                ref.external_id
                            ])

            sighted_by = sighters.keys()
            #elapsed = time.time() - start
            #self.debug("Processing sightings took", str(elapsed), "seconds for", observable.value)
            # Get Observable data from related ObservedData objects.
            # related_observables will be an array of threatstash.Observable
            # objects containing each STIX Observable's type and value as well
            # as the id from the parent ObservableData boject and the
            # relationship_type from the Relationship object.
            #start = time.time()
            related_observables = event.related_observables(observable.id)
            #elapsed = time.time() - start
            #self.debug("Retrieving", str(len(related_observables)), "relations took", str(elapsed), "seconds for", observable.value)
            if related_observables:
                # Iterate across the related ObservedData objects
                for related_observable in related_observables:
                    print(','.join([
                            observable.type,
                            observable.value,
                            observable.added_by,
                            related_observable.relationship_type,
                            related_observable.type,
                            related_observable.value,
                            related_observable.added_by,
                            str(sighted),
                            '|'.join(sighted_by),
                            last_seen,
                            external_reference
                        ]))
            else:
                print(','.join([
                        observable.type,
                        observable.value,
                        observable.added_by,
                        "", "", "", "",
                        str(sighted),
                        '|'.join(sighted_by),
                        last_seen,
                        external_reference
                    ]))
        return event
