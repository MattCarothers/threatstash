#!/usr/bin/env python3

import argparse
import yaml

from threatstash import Pipeline

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", help="Run with no logging output", action='store_true')
    parser.add_argument("-d", "--debug", help="Run with extra logging output", action='store_true')
    parser.add_argument("config_file", help="YAML configuration file", nargs=1)
    parser.add_argument("plugin_args", help="Additional arguments to pass to plugins", nargs="*")
    args = parser.parse_args()

    with open(args.config_file[0], 'r') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)

    if 'global' not in config:
        config['global'] = {}
    config['global']['args']  = args.plugin_args
    config['global']['quiet'] = args.quiet
    config['global']['debug'] = args.debug

    p = Pipeline(config)
    p.run()
