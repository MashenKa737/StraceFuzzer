import re
import signal

from src.utils.parser import StraceOutputParser
from src.engine.processes import TracerProcess, TraceeProcess


class ExecutionController:
    def __init__(self, args, fault, tolist, reporter, aterror):
        self.args = args
        self.fault = fault
        self.maximal_time_wait = 1
        self._reporter = reporter
        self._reporter.set_aterror(self.finish_with_error)
        self._succ_injections = tolist
        self._aterror = aterror
        self._tracee = None
        self._tracer = None

    def set_maximal_time_wait(self, new_mtw):
        self.maximal_time_wait = new_mtw

    def execute(self):
        self._tracee = TraceeProcess(target=self.args.target, args=self.args.target_args, program=self.args.prog)
        self._reporter.watch_tracee(self._tracee)

        self._tracee.start()
        self._reporter.handle_event(self._reporter.TRACEE_WAIT_FOR_STARTED_EVENT,
                                    success=self._tracee.wait_for_started())

        self._tracer = TracerProcess(pid=self._tracee.pid, fault=self.fault, program=self.args.prog)
        self._tracer.set_executable(self.args.strace_executable)
        parser = StraceOutputParser(self._tracer)
        parser.set_maximal_timestep(0.1)
        parser.timeout(self.maximal_time_wait)
        self._reporter.watch_tracer(self._tracer)

        self._tracer.start()
        # TODO here can be only two possible events:
        # tracer can terminate and therefore pop_line() will be None
        # or tracer doesn't terminate, and pop_line() returns not None sooner or later.
        self._reporter.handle_event(self._reporter.TRACER_STARTED_EVENT,
                                    first_line=parser.pop_line())

        parser.add_watcher(name="start", watcher=StraceOutputParser.REGEX_WATCHER(
            r'^execve\(\"' + re.escape(self._tracee.target) +
            r'", .*\) \= (?P<code>[-]?\d+)(?:$| (?P<errno>\w+) \((?P<strerror>(?:\w|\s)+)\)$)'))

        self._tracee.start_actual_tracee()
        watchers = parser.continue_until_watchers()

        self._reporter.handle_event(self._reporter.START_ACTUAL_TRACEE_EVENT,
                                    **({"code": int(watchers["start"].matcher.group("code")),
                                        "strerror": watchers["start"].matcher.group("strerror")}
                                       if len(watchers) != 0 else {}))

        parser.remove_watcher(name="start")
        parser.add_watcher(name="inject",
                           watcher=StraceOutputParser.ERROR_INJECT_WATCHER(self.fault.syscall, self.fault.when))

        previous_were = parser.watchers["inject"].were
        while True:
            watchers = parser.continue_until_watchers()
            if len(watchers) != 0:
                syscall = watchers["inject"].occasion
                parser.remove_watcher(name="inject")
                parser.add_watcher(name="sigsegv", watcher=StraceOutputParser.REGEX_WATCHER(
                    r'^\+{3} killed by SIGSEGV \(core dumped\) \+{3}'))

                watchers = parser.continue_until_watchers()
                if len(watchers) != 0:
                    assert self._tracee.exitcode(blocking=True) == - signal.SIGSEGV
                    self._succ_injections.append(fault=self.fault, context=syscall)

                break

            if len(watchers) == 0 and parser.watchers["inject"].were == previous_were:
                break

            previous_were = parser.watchers["inject"].were

        self.terminate_all()

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
