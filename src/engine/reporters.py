import re
import sys


class ErrorReporter:
    def __init__(self, program, tofile=sys.stderr):
        self.prog = program
        self.tofile = tofile
        self._tracee = None
        self._tracer = None
        self._aterror = None

    def watch_tracee(self, tracee):
        self._tracee = tracee

    def watch_tracer(self, tracer):
        self._tracer = tracer

    def unwatch(self):
        self._tracee = None
        self._tracee = None

    def set_aterror(self, aterror):
        self._aterror = aterror

    def _handle_error(self):
        self.unwatch()
        if self._aterror is not None:
            self._aterror()
        return False

    @staticmethod
    def handle_event(event, **kwargs):
        event(**kwargs)

    def _tracee_wait_for_started_event(self, success):
        if not success:
            print(self.prog + ": tracee was externally terminated: exitcode {}".
                  format(self._tracee.exitcode(blocking=True)), file=self.tofile)
            return self._handle_error()
        return True

    def _tracer_started_event(self, first_line):
        if first_line is None:
            print(self.prog + ": strace doesn't respond", file=self.tofile)
            # code = tracer.exitcode(blocking=True)
            # if code < 0:
            #    print(self.prog + ": tracee terminated with signal {}".
            #          format(signal.Signals(-code).name), file=sys.stderr)
            # else:
            #    print(self.prog + ": tracee terminated with exit status {}".
            #          format(code), file=sys.stderr)

        elif first_line == self._tracer.executable + ": Process {} attached".format(self._tracee.pid):
            return True
        elif re.match(r'^cannot run strace: .*$', first_line) \
                or re.match(r'^' + re.escape(self._tracer.executable) + r': .*$', first_line):
            print(self.prog + ': ' + first_line, file=self.tofile)

        else:
            print(self.prog + ': Unknown error', file=self.tofile)

        return self._handle_error()

    def _start_actual_tracee_event(self, code=None, strerror=None):
        if code is None:
            print(self.prog + ": actual tracee was not started", file=self.tofile)
        elif code == 0:
            return True
        elif code == -1:
            print(self.prog + ": cannot run tracee: {}".format(strerror), file=self.tofile)

        return self._handle_error()

    def _strace_output_not_syscall_event(self, line=None):
        if line is None:
            return True

        print(self.prog + ': Unexpected strace output line: ' + line, file=self.tofile)
        return self._handle_error()

    TRACEE_WAIT_FOR_STARTED_EVENT   = _tracee_wait_for_started_event
    TRACER_STARTED_EVENT            = _tracer_started_event
    START_ACTUAL_TRACEE_EVENT       = _start_actual_tracee_event
    STRACE_OUTPUT_NOT_SYSCALL_EVENT = _strace_output_not_syscall_event
