import dateutil.parser

from datetime import datetime, timezone

# STIX 2 SDO
from stix2 import ObservedData
# STIX 2 SRO
from stix2 import Relationship, Sighting
# STIX 2 Environment
from stix2 import Environment, MemoryStore, Filter
# STIX 2 Observables
from stix2 import AutonomousSystem, DomainName, EmailAddress, File, IPv4Address, IPv6Address, URL

import threatstash.observable

class Event():
    def __init__(self, observables=[], relationships=[], context=None):
        # STIX Environment to store STIX Objects
        self._env = Environment(store=MemoryStore())
        
        # Dict we can use to ensure observables are unique
        self._uniq = {}

        # STIX 2 objects are immutable once created, so we have to maintain our
        # own revocation list.
        self._revocation_list = {}

        # Observables are STIX 2 ObservedData objects
        for observed_data in observables:
            self._env.add(observed_data)
            for observable in observed_data.objects:
                # Store the ObservedData id in a dict keyed by the Observable
                # value. This will help prevent duplicates.
                self._uniq[observable.value] = observed_data.id

        # Relationships are STIX 2 Relationship objects
        for obj in relationships:
            self._env.add(obj)

        # Blob of text with additional context
        self._context = context

    def revoke(self, observed_data):
        """
        Revoke an ObservedData

        Parameters
        ----------
        observed_data: ObservedData object or id string
        """
        if type(observed_data) == str:
            _id = observed_data
        else:
            _id = observed_data.id
        self._revocation_list[_id] = True

    def revoked(self, observed_data):
        """
        Return true if an object is revoked or false if not

        Parameters
        ----------
        observed_data: ObservedData object or id string
        """
        if type(observed_data) == str:
            _id = observed_data
        else:
            _id = observed_data.id

        if _id in self._revocation_list:
            return True
        else:
            return False
    
    # Create external-references from a list of strings in the form of
    #   ["source_name1","external_id1","source_name2","external_id2",...]
    def _create_references(self, refs=[]):
        if len(refs) % 2 != 0:
            raise ValueError("refs list cannot have an odd number of items")

        external_references=[]
        # Run through the refs list two items at a time
        for source_name, external_id in zip(*[iter(refs)]*2):
            if '://' in external_id:
                url = external_id
            else:
                url = None
            external_references.append({
                    'source_name' : source_name,
                    'external_id' : external_id,
                    'url'         : url
                })
        return(external_references)


    # Add an ObservableData object populated with an Observable to an Event
    def add_observation(self, otype, value, added_by=None, refs=[]):
        """
        Parameters
        ----------
        otype : string
            The type of Observable, e.g. "ipv4-addr"
        value : string
            The value of the Observable, e.g. "10.0.0.1"
        added_by : string
            Optionally the name of the plugin adding the Observable
        refs : list
            List of strings in the form of ["source_name1","external_id1","source_name2","external_id2",...]

            source_name can be the name of a tool or plugin or whatever else is
            useful to you.  external_id is typically a reference such as an
            ID string, but you can put anything in it that suits your needs.
            Example: refs=["moloch-session", "180926-AQDFxWS0hCxPS5uba63ZJZr1"]
        """

        # Do we already have an ObservedData containing an Observable with this
        # value?  If so, return it rather than create a new one.
        if value in self._uniq:
            return self._env.get(self._uniq[value])
        else:
            if otype == "autonomous-system":
                observable = AutonomousSystem(value=value)
            elif otype == "domain-name":
                observable = DomainName(value=value)
            elif otype == "email-addr":
                observable = EmailAddress(value=value)
            elif otype in ["md5", "sha1", "sha256", "sha512", "ssdeep"]:
                observable = File(hashes={ otype : value })
            elif otype == "ipv4-addr":
                observable = IPv4Address(value=value)
            elif otype == "ipv6-addr":
                observable = IPv6Address(value=value)
            elif otype == "url":
                observable = URL(value=value)
            else:
                raise ValueError("Invalid Observable type: " + otype)

            external_references = self._create_references(refs)

            observed_data = ObservedData(
                    first_observed=datetime.utcnow(),
                    last_observed=datetime.utcnow(),
                    number_observed=1,
                    objects = { 0 : observable },
                    custom_properties = { 
                        'added_by' : added_by,
                        'refs' : external_references
                    }
            )
            #print("Added a new observed_data") # DEBUG
            #print(observed_data)               # DEBUG
            self._env.add(observed_data)
            self._uniq[value] = observed_data.id
            return(observed_data)
    
    # Add a STIX Relationship to an Event
    def add_relationship(self, source, target, relationship_type):
        """
        Parameters
        ----------
        source_obj : string or ObservedData object
            source object ID or object
        target_obj : string or ObservedData object
            target object ID or object
        relationship_type : string
        """
        if type(source) != str:
            source = source.id
        if type(target) != str:
            target = target.id

        r = Relationship(
            source_ref=source,
            target_ref=target,
            relationship_type=relationship_type
        )

        # Don't add duplicate relationships
        if not self._uniq.get(source + target + relationship_type):
            self._env.add(r)
            self._uniq[source + target + relationship_type] = True
        return(r)
    
    # Return all the relationships for a given source ObservedData
    def related_observables(self, observed_data, direction='related_to'):
        """
        Return all the observables from all the related ObservedData objects.

        Parameters
        ----------
        observed_data : a STIX 2 ObservedData object or id string
            The source object for which we want to find relationships
        direction: string
            'related_to' returns objects for which this object is the source of
             the relation
            'related_from' returns objects for which this object is the target
             of the relation
            'both' returns all all related objects, regardless of direction

        Return values are threatstash.Observable objects, which contain the
        ObservedData id, the type and value of each Observable in the
        ObservedData, and the relationship_type field from the Relationship
        object.
        """
        if direction == 'related_to':
            source_only = True
            target_only = False
        elif direction == 'related_from':
            source_only = False
            target_only = True
        elif direction == 'both':
            source_only = False
            target_only = False

        if type(observed_data) == str:
            _id = observed_data
        else:
            _id = observed_data.id

        relationships = []
        # Find all the Relationships in our Environment
        for r in self._env.relationships(_id, source_only=source_only, target_only=target_only):
            if self.revoked(r.source_ref) or self.revoked(r.target_ref):
                continue
            # Get the ObservedData object that is the target of each Relationship
            target_obj = self._env.get(r.target_ref)
            try:
                refs = target_obj.refs
            except:
                refs = []
            # Get the Observable objects in the ObservedData object
            for observable in target_obj.objects.values():
                # Create threatstash.Observable objects from the ObservedData,
                # Observable, and Relationship
                if observable.type == "file":
                    for hash_type, value in file.hashes.items():
                        relationships.append(
                                threatstash.observable.Observable(
                                    hash_type,
                                    value,
                                    _id = target_obj.id,
                                    added_by = target_obj.added_by,
                                    relationship_type = r.relationship_type,
                                    refs = refs
                                )
                            )
                else:
                    relationships.append(
                            threatstash.observable.Observable(
                                observable.type,
                                observable.value,
                                _id = target_obj.id,
                                added_by = target_obj.added_by,
                                relationship_type = r.relationship_type,
                                refs = refs
                            )
                        )
        return relationships
    
    # Return Sightings
    def sightings(self):
        """
        Return all Sighting objects in the Environment
        """
        sightings = []
        for sighting in self._env.query(Filter('type', '=', 'sighting')):
            if not self.revoked(sighting.sighting_of_ref):
                sightings.append(sighting)
        return sightings


    # Add a STIX Sighting to an Event
    def add_sighting(self, observed_data, first_seen=None, last_seen=None, sighted_by=None, refs=[], count=1):
        """
        Parameters
        ----------
        observed_data: ObservedData object or id string
        first_seen   : datetime.datetime or parsable string
        last_seen    : datetime.datetime or parsable string
        sighted_by   : string
            Name of the plugin or tool that sighted the ObservableData
        refs : list
            List of strings in the form of ["source_name1","external_id1","source_name2","external_id2",...]

            source_name can be the name of a tool or plugin or whatever else is
            useful to you.  external_id is typically a reference such as an
            ID string, but you can put anything in it that suits your needs.
            Example: refs=["moloch-session", "180926-AQDFxWS0hCxPS5uba63ZJZr1"]
        """
        if type(observed_data) == str:
            _id = observed_data
        else:
            _id = observed_data.id

        external_references = self._create_references(refs)

        # Default to now if no timestamp was given
        if not first_seen and not last_seen:
            first_seen = last_seen = datetime.now(timezone.utc)

        if first_seen:
            first_seen = dateutil.parser.parse(first_seen)

        if last_seen:
            last_seen = dateutil.parser.parse(last_seen)

        s = Sighting(
                _id,
                first_seen=first_seen,
                last_seen=last_seen,
                custom_properties = { 
                    'sighted_by' : sighted_by
                },
                external_references=external_references,
                count=count
        )
        self._env.add(s)
        return(s)

    # Return all the obsersables for sighted ObservedData objects
    def sighted_observables(self):
        """
        Return all the observables from all the sighted ObservedData objects.

        Return values are threatstash.Observable objects, which contain the
        ObservedData id, the type and value of each Observable in the
        ObservedData, and the first_seen and last_seen fields from the
        Sighting.
        """
        sightings = []
        # Find all the Sightings in our Environment
        for s in self._env.sightings():
            # Get the ObservedData object that is the target of each Sighting
            sighted_obj = self._env.get(s.sighting_of_ref)
            # Get the Observable objects in the ObservedData object
            for observable in sighted_obj.objects.values():
                # Create threatstash.Observable objects from the ObservedData,
                # Observable, and Sighting
                sightings.append(
                    threatstash.observable.Observable(
                        observable.type,
                        observable.value,
                        _id        = sighted_obj.id,
                        added_by   = sighted_obj.added_by,
                        first_seen = s.first_seen,
                        last_seen  = s.last_seen,
                        sighted_by = s.sighted_by
                    )
                )
        return sightings

    def sighted(self, observed_data):
        """
        Return true if there is a Sighting for an ObservedData

        Parameters
        ----------
        observed_data : string or ObservedData object
            The object or id to check
        """
        if self.revoked(observed_data):
            return False

        if type(observed_data) == str:
            _id = observed_data
        else:
            _id = observed_data.id

        if self._env.query(Filter('sighting_of_ref', '=', _id)):
            return True
        else:
            return False
    
    def sightings_of(self, observed_data):
        """
        Return the Sightings for a particular ObservedData

        Parameters
        ----------
        observed_data : string or ObservedData object
            The object or id to check
        """
        if self.revoked(observed_data):
            return False

        if type(observed_data) == str:
            _id = observed_data
        else:
            _id = observed_data.id

        return self._env.query(Filter('sighting_of_ref', '=', _id))
    
    # Getters and setters
    @property
    def observables(self):
        """
        Return all the Observables in all the ObservedData objects in our
        Environment
        """
        observables = []
        for observed_data in self.observations:
            #print("event.observables()") # DEBUG
            #print(observed_data)         # DEBUG
            try:
                # Adding custom property to a STIX2 ObservedData with a value
                # of [] results in the custom property not being added, so we
                # need a try/except here.
                refs = observed_data.refs
            except:
                refs = []
            for observable in observed_data.objects.values():
                # Create threatstash.Observable objects from the ObservedData,
                # and Observable
                if observable.type == "file":
                    for hash_type, value in observable.hashes.items():
                        observables.append(
                                threatstash.observable.Observable(
                                    hash_type,
                                    value,
                                    _id = observed_data.id,
                                    added_by = observed_data.added_by,
                                    refs = refs
                                )
                            )
                else:
                    observables.append(
                            threatstash.observable.Observable(
                                observable.type,
                                observable.value,
                                _id = observed_data.id,
                                added_by = observed_data.added_by,
                                refs = refs
                            )
                        )
        return observables
    
    @property
    def observation(self, _id):
        """
        Return a specifc ObservedData object from our Environment
        """
        if self.revoked(_id):
            return None
        return self._env.get(_id)

    @property
    def observations(self):
        """
        Return all the ObservedData objects in our Environment
        """
        observations = []
        for observed_data in self._env.query(Filter('type', '=', 'observed-data')):
            if not self.revoked(observed_data):
                observations.append(observed_data)
        return observations
    
    @property
    def relationships(self):
        """
        Return all the Relationships from our Environment
        """
        relationships = []
        for relationship in self._env.query(Filter('type', '=', 'relationship')):
            if self.revoked(r.source_ref) or self.revoked(r.target_ref):
                continue
            relationships.append(relationship)
        return relationships

    @property
    def context(self):
        return self._context

    @context.setter
    def context(self, context):
        self._context = context

    def to_dict(self):
        return {
            'observables' : self.observables,
            'context' : self.context
        }
