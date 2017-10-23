import argparse
import io
import os
import os.path
import sys

from src.engine.controllers import InjectionExecutionController
from src.engine.reporters import ErrorReporter
from src.engine.generator import InjectionGenerator
from src.utils.injection_writer import ListSuccessfulInjections


class ArgvHandler:
    def __init__(self):
        parser = argparse.ArgumentParser(description="injects errors into syscalls of targeted executable",
                                         allow_abbrev=False)
        parser.add_argument('-s', '--strace', action='store', default='strace',
                            help='path to strace executable', metavar='strace_executable', dest='strace_executable')

        parser.add_argument('-o', action='store', default=sys.stderr, type=argparse.FileType(mode='wt'),
                            help='write the %(prog)s output to the file "%(metavar)s" rather then to stderr',
                            metavar='filename', dest='file')

        parser.add_argument('target', action='store', help='targeted executable')

        parser.add_argument('args', action='store', nargs=argparse.REMAINDER,
                            help='arguments of targeted executable')

        self._args = parser.parse_args()
        self._program_name = os.path.basename(sys.argv[0])

    @property
    def program_name(self):
        return self._program_name

    @property
    def target(self):
        return self._args.target

    @property
    def strace_executable(self):
        return self._args.strace_executable

    @property
    def target_args(self):
        return self._args.args

    @property
    def output_file(self):
        return self._args.file

    @property
    def all_properties(self):
        return dict(program_name=self.program_name, output_file=self.output_file, target=self.target,
                    strace_executable=self.strace_executable, target_args=self.target_args)


if __name__ == '__main__':
    argvHandler = ArgvHandler()
    listSuccessfulInjections = ListSuccessfulInjections(output=argvHandler.output_file)

    error_reporter_output = io.StringIO()
    errorReporter = ErrorReporter(tofile=error_reporter_output, program=argvHandler.program_name)

    def print_all_and_exit():
        if not listSuccessfulInjections.is_empty():
            listSuccessfulInjections.print_until_end()
        print(error_reporter_output.getvalue(), file=sys.stderr, end='')
        exit(1)

    try:
        injectionGenerator = InjectionGenerator(reporter=errorReporter, aterror=print_all_and_exit,
                                                general_args=argvHandler.all_properties)

        for fault in injectionGenerator:
            controller = InjectionExecutionController(reporter=errorReporter, aterror=print_all_and_exit,
                                                      fault=fault, general_args=argvHandler.all_properties,
                                                      tolist=listSuccessfulInjections)
            controller.execute()
    except KeyboardInterrupt:
        pass

    if not listSuccessfulInjections.is_empty():
        listSuccessfulInjections.print_until_end()
    exit(0)
