import argparse
import io
import os
import os.path
import sys

from src.engine.controllers import ExecutionController
from src.engine.reporters import ErrorReporter
from src.model.fault import Fault
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
        self._prog = os.path.basename(sys.argv[0])

    @property
    def prog(self):
        return self._prog

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


# should be linked with other part of project in any way
class InjectionGenerator:
    def __init__(self):
        self._generated = False

    def __iter__(self):
        return self

    def __next__(self):
        if not self._generated:
            self._generated = True
            return Fault(syscall="open", error="ENOENT", when=4)

        raise StopIteration


if __name__ == '__main__':
    argvHandler = ArgvHandler()
    listSuccessfulInjections = ListSuccessfulInjections(output=argvHandler.output_file)

    error_reporter_output = io.StringIO()
    errorReporter = ErrorReporter(tofile=error_reporter_output, program=argvHandler.prog)

    def print_all_and_exit():
        if not listSuccessfulInjections.is_empty():
            listSuccessfulInjections.print_until_end()
        print(error_reporter_output.getvalue(), file=sys.stderr, end='')
        exit(1)

    for fault in InjectionGenerator():
        controller = ExecutionController(args=argvHandler, fault=fault,
                                         tolist=listSuccessfulInjections,
                                         reporter=errorReporter,
                                         aterror=print_all_and_exit)
        controller.execute()

    if not listSuccessfulInjections.is_empty():
        listSuccessfulInjections.print_until_end()
    exit(0)
