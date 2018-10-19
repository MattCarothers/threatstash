import inspect
import logging
import plugins
import threatstash.event

class Pipeline():
    """
    The Pipeline class loads Plugin modules and runs Events through them.
    """
    def __init__(self, config):
        self._plugins = {}
        self._config  = config
        # Enable of disable debugging output based on the config
        if 'global' in self.config:
            if 'quiet' in self.config['global'] and self.config['global']['quiet']:
                logging.basicConfig(level=logging.WARN)
            if 'debug' in self.config['global'] and self.config['global']['debug']:
                logging.basicConfig(level=logging.DEBUG, format='%(levelname) -5s %(message)s')
            else:
                logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')

        # Build the list of plugins we want to load
        to_load = {}
        for plugin_config in config['plugins']:
            to_load[plugin_config['name']] = True

        # Iterate through the modules in our plugins directory
        for name, obj in inspect.getmembers(plugins):
            if inspect.isclass(obj) and name != "value":
                self.debug("Found available plugin: " + name)
                # Instantiate the plugin and find out its name
                Plugin = getattr(plugins, name)
                plugin = Plugin(config)
                # Load the module if it's in our list of things to load
                if plugin.name in to_load:
                    self._plugins[plugin.name] = plugin
                    self.info("Loaded plugin " + plugin.name + " from module " + name)
                    self.debug(" |-> Type:    " + plugin.type)
                    if plugin.observable_types:
                        self.debug(" `-> Handles: " + ", ".join(plugin.observable_types))
                    else:
                        self.debug(" `-> Handles: any")
        # Validate config
        if 'plugins' not in self.config:
            raise RuntimeError("No plugins are configured")
        for plugin_config in self.config['plugins']:
            if 'name' not in plugin_config:
                raise RuntimeError("Configured plugin missing name:" + str(plugin_config))
            plugin_name = plugin_config['name']
            if plugin_name not in self.plugins:
                raise RuntimeError("Configured plugin " + plugin_name + " does not exist")

    def run(self):
        """
        Create a new Event and run all applicable Plugins against it.
        """
        event = threatstash.event.Event()
        for plugin_config in self.config['plugins']:
            plugin_name = plugin_config['name']
            self.info("Running " + plugin_name)
            p = self.plugins[plugin_name]
            p.configure(plugin_config)
            p.init()
            # Input plugins gather IOCs rather than operating on them
            if p.type == "input":
                p.run(event)
            # Some plugins operate on the context field rather than
            # observables
            elif p.handles("context"):
                p.run(event)
            else:
                # If this isn't an input plugin, check the Event's IOCs against
                # those handled by the plugin before running it.
                for observable in event.observables:
                    self.debug(" |-> Testing " + plugin_name + " against " + observable.type)
                    if p.handles(observable.type):
                        self.debug(" `-> Success!")
                        event = p.run(event)
                        break
                    else:
                        self.debug(" `-> Failure")

    @property
    def plugins(self):
        return self._plugins
    
    @property
    def config(self):
        return self._config
    
    def debug(self, message):
        if type(message) == list:
            message = " ".join(message)
        logging.debug('[pipeline] ' + message)

    def info(self, message):
        if type(message) == list:
            message = " ".join(message)
        logging.info('[pipeline] ' + message)
    
    def warn(self, message):
        if type(message) == list:
            message = " ".join(message)
        logging.warn('[pipeline] ' + message)
