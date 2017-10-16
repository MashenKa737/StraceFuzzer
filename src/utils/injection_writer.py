import sys

from src.model.fault import Fault


class ListSuccessfulInjections:
    def __init__(self, output=sys.stderr):
        self._header = '--- list of injections, which induced SIGSEGV in targeted executable ---'
        self._tail = ' end of list '.center(len(self._header), '-')
        self._separator = "".ljust(len(self._header), '-')

        self._entries = []
        self._header_printed = False

        if isinstance(output, (str, bytes, int)):
            self._output = open(output, mode="wt")
        else:
            self._output = output

    def append(self, fault: Fault, context: str):
        self._entries.append(dict(fault=fault, context=context))

    def print(self):
        if not self._header_printed:
            print(self._header, file=self._output)
            self._header_printed = True
        for entry in self._entries:
            print(self._separator, file=self._output)
            print("Syscall: {syscall}\nError: {error}\nAppearance: {when}".
                  format(**entry["fault"].all_parts()), file=self._output)

            # TODO add more clever printing context if it is too large
            print("Context: {}".format(entry["context"]), file=self._output)

        self._entries.clear()

    def print_until_end(self):
        self.print()
        print(self._tail, file=self._output)

    def is_empty(self):
        return len(self._entries) == 0
