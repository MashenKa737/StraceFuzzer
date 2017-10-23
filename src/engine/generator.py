import random
import errno

from src.engine.controllers import GeneratorExecutionController
from src.model.fault import Fault
from src.engine.reporters import ErrorReporter


class InjectionGenerator:
    LIST_AVAILABLE_ERRORS = list(errno.errorcode.keys())

    def __init__(self, reporter: ErrorReporter, aterror, general_args: dict, timeout=1):
        self._syscallList = []
        self._syscallCount = {}
        self._syscallListDropped = []
        self._syscallCountDropped = {}
        self._generatorController = GeneratorExecutionController(reporter=reporter, aterror=aterror,
                                                                 general_args=general_args)

        self._generatorController.set_maximal_time_wait(timeout)

    def __iter__(self):
        self._generatorController.execute()
        self._syscallList = self._generatorController.list_syscalls
        for syscall in self._syscallList:
            if syscall not in self._syscallCount:
                self._syscallCount[syscall] = 0
            self._syscallCount[syscall] += 1

        self._syscallListDropped = self._generatorController.list_dropped_syscalls
        for syscall in self._syscallListDropped:
            if syscall not in self._syscallCountDropped:
                self._syscallCountDropped[syscall] = 0
            self._syscallCountDropped[syscall] += 1

        return self

    def __next__(self):
        syscall = self._syscallList[random.randrange(len(self._syscallList))]
        when = random.randrange(self._syscallCount[syscall]) + 1
        when += self._syscallCountDropped.get(syscall, 0)
        error = errno.errorcode[random.choice(InjectionGenerator.LIST_AVAILABLE_ERRORS)]

        fault = Fault(syscall=syscall, error=error, when=when)
        return fault
