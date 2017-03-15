import re
import requests

from configman import Namespace
from configman.dotdict import DotDict

from socorro.lib.transform_rules import Rule


class RawCrashFromPing(Rule):
    """Reorganize a crash ping into the structure expected for a raw crash"""

    def _action(self, raw_crash, raw_dumps, processed_crash, processor_meta):
        crash_ping = DotDict()
        crash_ping.update(raw_crash)
        raw_crash.clear()

        # crash annotations
        raw_crash.update(crash_ping.payload.metadata)

        # TODO: not sure if this is the right uuid
        raw_crash.uuid = crash_ping.payload.crashId

        # keep these around for further ping-specific processing
        raw_crash.stackTraces = crash_ping.payload.stackTraces
        raw_crash.environment = crash_ping.environment
        raw_crash.hasCrashEnvironment = crash_ping.payload.hasCrashEnvironment

        return True


class SymbolicatePingRule(Rule):
    """Get function names for stacks from symbolication server"""

    required_config = Namespace()
    required_config.add_option(
        'symbolication_api_url',
        doc='url of the symbolication server',
        default='http://localhost:8080/'
    )

    def version(self):
        return '1.0'

    @staticmethod
    def debug_pair(module):
        if not ('debug_file' in module and 'debug_id' in module):
            return None
        return (module['debug_file'], module['debug_id'])

    def _action(self, raw_crash, raw_dumps, processed_crash, processor_meta):
        try:
            stack_traces = raw_crash['stackTraces']

            stack_status = stack_traces.get('status', 'MISSING')

            if stack_status != 'OK':
                self.config.logger.warning(
                    'SymbolicatePingRule: stack trace status not OK: %s',
                    stack_status
                )
        except KeyError:
            self.config.logger.warning(
                'SymbolicatePingRule: no stack trace'
            )
            return True

        processed = DotDict()

        processed.status = stack_status
        processed.main_module = stack_traces.main_module
        processed.crash_info = stack_traces.crash_info

        processed.system_info = DotDict()
        os_name = raw_crash.environment.system.os.name
        if os_name == 'Windows_NT':
            processed.system_info.os = 'Windows NT'
        elif os_name == 'Darwin':
            processed.system_info.os = 'Mac OS X'
        else:
            processed.system_info.os = os_name
        # TODO this should probably have service pack version as well, other
        # details
        processed.system_info.os_ver = raw_crash.environment.system.os.version

        processed.modules = []
        modules_to_symbolicate = []

        for idx, m in enumerate(stack_traces.modules):
            processed_module = DotDict()
            processed.modules.append(processed_module)

            for key in ['base_addr', 'end_addr', 'code_id', 'debug_file',
                        'debug_id', 'filename', 'version']:
                if key in m:
                    processed_module[key] = m[key]

            # prepare this module for symbol lookup
            if 'debug_file' in m and 'debug_id' in m and m.debug_id != '':
                mp = self.debug_pair(m)
                if mp not in modules_to_symbolicate:
                    modules_to_symbolicate.append(mp)
            else:
                processed_module.missing_symbols = True

        processed.threads = []
        threads_to_symbolicate = []

        for thread_idx, thread in enumerate(stack_traces.threads):
            processed_thread = DotDict()
            processed_thread.frames = []
            processed.threads.append(processed_thread)

            for idx, frame in enumerate(thread.frames):
                processed_frame = DotDict()
                processed_thread.frames.append(processed_frame)

                frames_to_symbolicate = []
                threads_to_symbolicate.append(frames_to_symbolicate)

                processed_frame.frame = idx
                processed_frame.trust = frame.trust

                ip_int = int(frame['ip'], 16)
                processed_frame.offset = frame['ip']

                # missing until proven found
                processed_frame.missing_symbols = True

                if 'module_index' not in frame:
                    continue

                module = stack_traces.modules[frame.module_index]
                module_offset_int = ip_int - int(module.base_addr, 16)

                processed_frame.module = module.filename
                processed_frame.module_offset = '0x%x' % module_offset_int

                # prepare this frame for symbol lookup
                if 'debug_file' in module and 'debug_id' in module:
                    mp = self.debug_pair(module)
                    if mp in modules_to_symbolicate:
                        frames_to_symbolicate.append(
                            (processed_frame,
                             [modules_to_symbolicate.index(mp),
                              module_offset_int]))

        # build symbolication request
        sym_request = {
            'stacks': [[f for (_, f) in t] for t in threads_to_symbolicate],
            'memoryMap':
                [[debug_file, debug_id] for
                 (debug_file, debug_id) in modules_to_symbolicate],
            'version': 4}

        # make request
        try:
            sym_result = requests.post(self.config.symbolication_api_url,
                                       json=sym_request).json()
        except IOError as e:
            self.config.logger.error(
                'SymbolicatePingRule: '
                'exception during symbolication request:\n%s',
                e)
            sym_result = None

        if sym_result:
            # mark missing_symbols by whether the module was known
            for idx, module in enumerate(processed.modules):
                mp = self.debug_pair(module)
                if mp in modules_to_symbolicate:
                    module_symbolicate_idx = modules_to_symbolicate.index(mp)
                    module.missing_symbols = \
                        sym_result['knownModules'][module_symbolicate_idx]

            # retrieve function names
            stacks = sym_result['symbolicatedStacks']
            for thread, thread_result in zip(threads_to_symbolicate, stacks):
                for fp, result in zip(thread, thread_result):
                    frame = fp[0]
                    module = fp[1][0]
                    if sym_result['knownModules'][module]:
                        function_name = re.match(
                            r"\A(.+) (\(in .+\))\Z", result
                        ).group(1)
                        # check that name isn't just a hex address
                        if not re.match(r"\A0x[0-9a-fA-F]+\Z", function_name):
                            frame.missing_symbols = False
                            frame.function = function_name

        processed_crash.json_dump = processed
        processed_crash.mdsw_status_string = processed.status
        processed_crash.success = processed.status == 'OK'

        return True
