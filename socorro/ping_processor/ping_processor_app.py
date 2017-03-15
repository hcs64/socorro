#! /usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import json

from configman import Namespace
from configman.converters import class_converter

from socorro.app.socorro_app import App, main
from socorro.lib.util import DotDict


class PingProcessorApp(App):
    """Generate a signature for a crash ping"""

    app_name = 'ping_processor_app'
    app_version = '0.1'
    app_description = __doc__

    required_config = Namespace()

    required_config.namespace('ping_processor')

    required_config.ping_processor.add_option(
        'processor_class',
        doc='the class that transforms raw crashes into processed crashes',
        default='socorro.ping_processor.ping_processor.PingProcessorAlgorithm',
        from_string_converter=class_converter
    )

    def main(self):
        self.config.processor_name = self.app_instance_name

        processor = self.config.ping_processor.processor_class(
            self.config.ping_processor)

        for filename in sys.stdin:
                infile = open(filename.strip(), 'r')
                raw_crash = json.load(infile, object_hook=DotDict)
                infile.close()

                dumps = []
                processed_crash = DotDict()

                # TODO: not sure if this is the right UUID to be using
                # Put the UUID in place early so shows in the processor logs
                raw_crash.uuid = raw_crash.payload.crashId

                processed_crash = processor.process_crash(
                        raw_crash,
                        dumps,
                        processed_crash
                )

                print(processed_crash.signature)
                sys.stdout.flush()

if __name__ == '__main__':
    main(PingProcessorApp)
