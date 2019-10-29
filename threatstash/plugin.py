import logging

class Plugin(dict):
    """
    Superclass for all plugins.
    """
    def __init__(self, name, ptype, observable_types, required_parameters=[], config={}):
        """
        Parameters
        ----------
        name : string
            Name of the plugin, e.g. filter-oil

        type : string
            Type of plugin. input, filter, or output

        observable_types : list of strings
            Types of observables handled by this plugin, e.g. 'ip4', 'domain'

        config : dict
            Configuration options.  Options with the 'global' key will be
            merged with options with a key matching this plugin's name.
        """
        self._name = name

        assert(ptype == "input" or ptype == "filter" or ptype == "output")
        self._type = ptype

        self._observable_types = observable_types
        
        self._required_parameters = required_parameters
        
        # Generate a dict of IOC types we handle
        self._handles = {}
        for observable_type in observable_types:
            self._handles[observable_type] = True

        self._config = {}
        # Merge in the 'global' section of the config
        if 'global' in config:
            self._config = { **config['global'] }
        # Merge in configuration specific to this plugin
        if self.name in config:
            self._config = { **self._config, **config[self.name] }

        # Enable of disable debugging output based on the config
        if self.config['debug']:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

    # Add additional configuration for this particular instance
    def configure(self, config):
        self._config = { **self._config, **config }

    # Perform any initialization that needs to take place after configuration
    # has been supplied
    def init(self):
        self.check_config()
        return True

    # Getters
    @property
    def name(self):
        return self._name

    @property
    def type(self):
        return self._type

    @property
    def observable_types(self):
        return self._observable_types
    
    @property
    def config(self):
        return self._config

    # Return true if this plugin handles the provided IOC type.  If the IOC
    # type list for the plugin is empty, it is assumed to handle all types.
    def handles(self, observable_type):
        # Normalize to lowercase
        observable_type = observable_type.lower()
        if not len(self._handles):
            return True
        elif observable_type in self._handles:
            return True
        else:
            return False

    def check_config(self):
        # Check for required config parameters
        for parameter in self._required_parameters:
            if parameter not in self.config:
                raise KeyError("Missing configuration parameter for " + self.name + ": " + parameter)

    # Skeleton handler.  Return the event unchanged.
    def run(self, event):
        return event

    def debug(self, *message):
        message = " ".join(message)
        logging.debug('[' + self.name + '] ' + message)

    def info(self, *message):
        message = " ".join(message)
        logging.info('[' + self.name + '] ' + message)
    
    # Output a string reprsentation of the plugin
    def __repr__(self):
        return("%s (%s) [%s]" % (self.name, self.type, ", ".join(sorted(self.observable_types))))

    # Output a dict reprsentation of the plugin
    def to_dict(self):
        return {
            'name' : self.name,
            'type' : self.type,
            'observable_types' : self.observable_types
        }
