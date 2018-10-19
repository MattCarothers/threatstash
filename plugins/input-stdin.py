import threatstash.plugin
import threatstash.observable
import sys

__PLUGIN_NAME__ = 'input-stdin'
__PLUGIN_TYPE__ = 'input'
__IOC_TYPES__ = [ ]
__REQUIRED_PARAMETERS__ = [ ]

class StdinInput(threatstash.plugin.Plugin):
    def __init__(self, config = {}):
        super().__init__(__PLUGIN_NAME__, __PLUGIN_TYPE__, __IOC_TYPES__, __REQUIRED_PARAMETERS__, config)

    def run(self, event):
        """
        Read stdin and populate an Event.
        
        Set the event's context field to the input.  Also
        create a 'text' IOC with the same data.
        """
        event.context = "\n".join(sys.stdin.readlines())
        return event
