# Import everything in this directory that looks like input-*, filter-*, or
# output-*
__all__ = []

import pkgutil
import inspect

for loader, name, is_pkg in pkgutil.walk_packages(__path__):
    #print("loader", loader, "name", name, "is_pkg", is_pkg)
    for pattern in 'input-', 'filter-', 'output-':
        if name.startswith(pattern):
            module = loader.find_module(name).load_module(name)
            #print("\tmodule", module)

            for name, value in inspect.getmembers(module):
                #print("\t\tname", name, "value", value)
                if name.startswith('__'):
                    continue

                #print("\t\t\tname does not start with __")
                globals()[name] = value
                #print("\t\t\tglobals()[" + str(name) + "] = " + str(value))
                __all__.append(name)
                #print("\t\t\t__all__.append(" + str(name) + ")")

#print("__all__", str(__all__))
