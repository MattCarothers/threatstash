# Helper class that glues together information between STIX 2 ObservedData,
# Observation, Relationship, and Sighting objects

class Observable():
    def __init__(self, _type, value, _id=None, added_by=None,
            relationship_type=None, first_seen=None, last_seen=None):
        self._id    = _id
        self._type  = _type
        self._value = value
        self._added_by = added_by
        self._first_seen = first_seen
        self._last_seen  = last_seen
        self._relationship_type = relationship_type

    # Getters
    @property
    def id(self):
        return self._id
    
    @property
    def type(self):
        return self._type

    @property
    def value(self):
        return self._value

    @property
    def added_by(self):
        return self._added_by

    @property
    def first_seen(self):
        return self._first_seen

    @property
    def last_seen(self):
        return self._last_seen

    @property
    def relationship_type(self):
        return self._relationship_type

    # String representaiton of the observable
    def __repr__(self):
        return self.value
        #return "%s / %s / %s" % (self.type, self.value, self.description)

    def to_dict(self):
        #return str(self.__dict__())
        return {
            'id' : self.id,
            'type' : self.type,
            'value' : self.value,
            'relationship_type' : self.relationship_type
        }
