import re
import signal

from src.utils.parser import StraceOutputParser
from src.engine.processes import TracerProcess, TraceeProcess
from src.engine.reporters import ErrorReporter
from src.model.fault import Fault
from src.utils.injection_writer import ListSuccessfulInjections


class ExecutionController:
    MAXIMAL_TIME_WAIT_ON_START_PROCESSES = 10

    def __init__(self, reporter: ErrorReporter, aterror, processes_args: dict):
        self.args = processes_args
        self.maximal_time_wait = 1
        self._listDroppedSyscalls = []
        self._reporter = reporter
        self._reporter.set_aterror(self.finish_with_error)
        self._aterror = aterror

        self._tracee = TraceeProcess(target=self.args["target"], args=self.args["target_args"],
                                     program=self.args["program_name"])
        self._tracer = TracerProcess(pid=None, args=self.args["strace_args"],
                                     program=self.args["program_name"])
        self._tracer.set_executable(self.args["strace_executable"])

        self._reporter.watch_tracee(self._tracee)
        self._reporter.watch_tracer(self._tracer)

        self._parser = StraceOutputParser(self._tracer)
        self._parser.set_maximal_timestep(0.1)
        self._parser.timeout(self.maximal_time_wait)

    def set_maximal_time_wait(self, new_mtw):
        self.maximal_time_wait = new_mtw
        self._parser.timeout(self.maximal_time_wait)

    def start_processes(self):
        self._parser.timeout(ExecutionController.MAXIMAL_TIME_WAIT_ON_START_PROCESSES)

        self._tracee.start()
        self._reporter.handle_event(self._reporter.TRACEE_WAIT_FOR_STARTED_EVENT,
                                    success=self._tracee.wait_for_started())

        self._tracer.set_tracee_pid(self._tracee.pid)
        self._tracer.start()
        # TODO here can be only two possible events:
        # tracer can terminate and therefore pop_line() will be None
        # or tracer doesn't terminate, and pop_line() returns not None sooner or later.
        self._reporter.handle_event(self._reporter.TRACER_STARTED_EVENT,
                                    first_line=self._parser.pop_line())

        self._parser.add_watcher(name="drop", watcher=StraceOutputParser.REMEMBER_SYSCALLS_WATCHER())
        self._parser.add_watcher(name="start", watcher=StraceOutputParser.REGEX_WATCHER(
            r'^execve\(\"' + re.escape(self._tracee.target) +
            r'", .*\) \= (?P<code>[-]?\d+)(?:$| (?P<errno>\w+) \((?P<strerror>(?:\w|\s)+)\)$)'))

        self._tracee.start_actual_tracee()
        watchers = self._parser.continue_until_watchers()

        self._reporter.handle_event(self._reporter.STRACE_OUTPUT_NOT_SYSCALL_EVENT,
                                    line=watchers["drop"].occasion if "drop" in watchers else None)

        self._reporter.handle_event(self._reporter.START_ACTUAL_TRACEE_EVENT,
                                    **({"code": int(watchers["start"].matcher.group("code")),
                                        "strerror": watchers["start"].matcher.group("strerror")}
                                       if "start" in watchers else {}))

        self._parser.pop_line()
        self._listDroppedSyscalls = self._parser.watchers["drop"].list_syscalls
        self._parser.remove_watcher(name="drop")
        self._parser.remove_watcher(name="start")
        self._parser.timeout(self.maximal_time_wait)
        # here can and should be successive watching for strace output

    @property
    def list_dropped_syscalls(self):
        return self._listDroppedSyscalls

    def finish_with_error(self):
        self.terminate_all()
        self._reporter.set_aterror(None)
        self._aterror()
        assert False  # self._aterror() should end execution

    def terminate_all(self):
        if self._tracee is not None:
            self._tracee.terminate()
        if self._tracer is not None:
            self._tracer.terminate()
        self._tracee = None
        self._tracer = None


class InjectionExecutionController(ExecutionController):
    def __init__(self, reporter: ErrorReporter, aterror, fault: Fault, general_args: dict,
                 tolist: ListSuccessfulInjections):
        general_args["strace_args"] = ["-e", str(fault)]
        super().__init__(reporter=reporter, aterror=aterror,
                         processes_args=general_args)
        self.fault = fault
        self._succ_injections = tolist

    def execute(self):
        self.start_processes()
        self._parser.add_watcher(name="inject",
                                 watcher=StraceOutputParser.ERROR_INJECT_WATCHER(self.fault.syscall, self.fault.when))

        previous_were = self._parser.watchers["inject"].were
        while True:
            watchers = self._parser.continue_until_watchers()
            if len(watchers) != 0:
                syscall = watchers["inject"].occasion
                self._parser.remove_watcher(name="inject")
                self._parser.add_watcher(name="sigsegv", watcher=StraceOutputParser.REGEX_WATCHER(
                    r'^\+{3} killed by SIGSEGV \(core dumped\) \+{3}$'))

                watchers = self._parser.continue_until_watchers()
                if len(watchers) != 0:
                    assert self._tracee.exitcode(blocking=True) == - signal.SIGSEGV
                    self._succ_injections.append(fault=self.fault, context=syscall)

                break

            if len(watchers) == 0 and self._parser.watchers["inject"].were == previous_were:
                break

            previous_were = self._parser.watchers["inject"].were

        self.terminate_all()


class GeneratorExecutionController(ExecutionController):
    def __init__(self, reporter: ErrorReporter, aterror, general_args: dict):
        general_args["strace_args"] = []
        super().__init__(reporter=reporter, aterror=aterror, processes_args=general_args)
        self._list_syscalls = []

    def execute(self):
        self.start_processes()
        self._parser.add_watcher(name="counter", watcher=StraceOutputParser.REMEMBER_SYSCALLS_WATCHER())

        watchers = self._parser.continue_until_watchers()
        self._reporter.handle_event(self._reporter.STRACE_OUTPUT_NOT_SYSCALL_EVENT,
                                    line=watchers["counter"].occasion if "counter" in watchers else None)

        self._list_syscalls = self._parser.watchers["counter"].list_syscalls
        self._parser.remove_watcher("counter")
        self.terminate_all()

    @property
    def list_syscalls(self):
        return self._list_syscalls
