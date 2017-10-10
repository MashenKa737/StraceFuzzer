import sys
import os
import signal
import time
import select
import argparse
import re
import os.path


class ArgvHandler:
    def __init__(self):
        parser = argparse.ArgumentParser(description="injects errors into syscalls of targeted executable",
                                         allow_abbrev=False)
        parser.add_argument('-s', '--strace', action='store', default='strace',
                            help='path to strace executable', dest='strace_executable')
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


class Fault:
    def __init__(self, syscall: str, error: str, when: int):
        self._syscall = syscall
        self._error = error
        self._when = when

    @property
    def syscall(self):
        return self._syscall

    @property
    def error(self):
        return self._error

    @property
    def when(self):
        return self._when

    def all_parts(self):
        return dict(syscall=self.syscall, error=self.error, when=self.when)

    def __str__(self):
        return "fault=" + self._syscall + ":error=" + self._error + ":when=" + str(self._when)


# should be linked with other part of project in any way
class InjectionGenerator:
    def __init__(self):
        pass

    def __iter__(self):
        return self

    def __next__(self):
        return Fault(syscall="open", error="ENOENT", when=4)


class AbstractPipeProcess:
    def __init__(self, program):
        self.pid = None
        self._exitcode = None
        self.prog = program

    def start(self):
        raise NotImplementedError

    def terminate(self):
        raise NotImplementedError

    def exitcode(self, blocking=False):
        self._update_exitcode(blocking)
        return self._exitcode

    # blocking mode of waitpid may be useful,
    # if we are sure that process was terminated or
    # must terminate in the near future
    def _update_exitcode(self, blocking=False):
        if self._exitcode is not None:
            return

        flag = 0 if blocking else os.WNOHANG

        (pid, status) = os.waitpid(self.pid, flag)
        if pid == 0:
            return

        if os.WIFSIGNALED(status):
            self._exitcode = - os.WTERMSIG(status)
        elif os.WIFEXITED(status):
            self._exitcode = os.WEXITSTATUS(status)

    def _say_parent_was_killed(self):
        print(self.prog + ": main program was terminated", file=sys.stderr)


# the bicycle for subprocess.Popen
class TracerProcess(AbstractPipeProcess):
    def __init__(self, pid, fault, program):
        AbstractPipeProcess.__init__(self, program)
        (self._r, self._w) = None, None
        self._tracee_pid = pid
        self._fault = fault
        self.err = None
        self.executable = 'strace'
        self.args = "-p", str(self._tracee_pid), "-e", str(self._fault)

    # call it only once
    # override
    def start(self):
        # Blocking mode of pipe is used in tracer process in order to guarantee
        # that there is no data loss of strace output, though it may be slower
        # non-blocking mode of pipe is used in parent process
        # for convenient usage of self.err.read().
        # Otherwise, we will have to use only low-level os.read
        (self._r, self._w) = os.pipe2(0)
        self.pid = os.fork()
        if self.pid == 0:
            self._execute_tracer()

        os.close(self._w)
        os.set_blocking(self._r, False)
        os.set_inheritable(self._r, False)
        self.err = os.fdopen(self._r, mode="rt")

    def set_executable(self, executable):
        self.executable = executable

    def readbuf(self, timeout):
        buf = str()
        clock = time.perf_counter()
        timeout_left = timeout
        while True:
            (readable, _, _) = select.select([self.err], [], [], timeout_left)
            if len(readable) == 0:
                break
            buf = buf + readable[0].read()
            if self.exitcode() is not None:
                (readable, _, _) = select.select([self.err], [], [], 0)
                if len(readable) != 0:
                    buf = buf + readable[0].read()
                break

            timeout_left = timeout - (time.perf_counter() - clock)
            if timeout_left <= 0:
                break

        return buf

    # override
    def terminate(self):
        if self.exitcode() is None:
            os.kill(self.pid, signal.SIGKILL)
            self._update_exitcode(blocking=True)

        if self.err is not None:
            self.err.close()
            self.err = None

    def _execute_tracer(self):
        os.close(self._r)
        try:
            os.dup2(self._w, sys.stderr.fileno())
            os.close(self._w)
            os.execlp(self.executable, self.executable, *self.args)
        except OSError as exc:
            # It will be send through pipe, if dup2 call was successful
            try:
                print("cannot run strace: {}".format(exc.strerror), file=sys.stderr)
            except BrokenPipeError:
                self._say_parent_was_killed()
            exit(1)


class TraceeProcess(AbstractPipeProcess):
    def __init__(self, target, args, program):
        AbstractPipeProcess.__init__(self, program)
        (self._rstart, self._wstart) = None, None
        (self._rwait, self._wwait) = None, None
        self.target = target
        self.args = args

    # call it only once
    # override
    def start(self):
        (self._rstart, self._wstart) = os.pipe2(os.O_CLOEXEC)
        (self._rwait, self._wwait) = os.pipe2(os.O_CLOEXEC)
        self.pid = os.fork()
        if self.pid == 0:
            self._execute_tracee()

        os.close(self._wwait)
        os.close(self._rstart)
        os.set_inheritable(self._rwait, False)
        os.set_inheritable(self._wstart, False)

    def _execute_tracee(self):
        os.close(self._rwait)
        os.close(self._wstart)
        try:
            os.write(self._wwait, b'wait')
            msg = os.read(self._rstart, len(b'start'))
            os.close(self._rstart)
            if msg == b'start':
                os.execlp(self.target, self.target, *self.args)

        except BrokenPipeError:
            os.close(self._rstart)
            self._say_parent_was_killed()
        except OSError:
            pass

        os.close(self._wwait)
        exit(1)

    # call it only after start method and only once
    def wait_for_started(self):
        # It cannot be blocked in any way and might execute relatively quickly
        msg = os.read(self._rwait, len(b'wait'))
        return msg == b'wait'

    # call it only once
    def start_actual_tracee(self):
        success = True
        try:
            os.write(self._wstart, b'start')
        except BrokenPipeError:
            success = False
        return success

    # override
    def terminate(self):
        if self.exitcode() is None:
            os.kill(self.pid, signal.SIGKILL)
            self._update_exitcode(blocking=True)

        if self._wstart is not None:
            os.close(self._wstart)
            self._wstart = None

        if self._rwait is not None:
            os.close(self._rwait)
            self._rwait = None


class Watcher:
    # used as decorator for functions __call__ in all Watcher's successors
    def watcher_call(call):
        def wrapper(self, line):
            if self._occasion is not None:
                return True
            success = call(self, line)
            if success:
                self._occasion = line
            return success

        return wrapper

    def __init__(self):
        self._occasion = None

    @watcher_call
    def __call__(self, line):
        return True

    @property
    def occasion(self):
        return self._occasion


class ExecutionController:
    def __init__(self, args, fault):
        self.args = args
        self.fault = fault

    def start(self):
        reporter = ErrorReporter(tofile=sys.stderr, program=self.args.prog)

        tracee = TraceeProcess(target=self.args.target, args=self.args.target_args, program=self.args.prog)
        reporter.watch_tracee(tracee)

        tracee.start()
        reporter.handle_event(ErrorReporter.TRACEE_WAIT_FOR_STARTED_EVENT,
                              success=tracee.wait_for_started())

        tracer = TracerProcess(pid=tracee.pid, fault=self.fault, program=self.args.prog)
        tracer.set_executable(self.args.strace_executable)
        parser = StraceOutputParser(tracer)
        reporter.watch_tracer(tracer)

        tracer.start()
        # TODO here can be only two possible events:
        # tracer can terminate and therefore pop_line() will be None
        # or tracer doesn't terminate, and pop_line() returns not None sooner or later.
        reporter.handle_event(ErrorReporter.TRACER_STARTED_EVENT,
                              first_line=parser.timeout(1).pop_line())

        parser.add_watcher(name="start", watcher=StraceOutputParser.REGEX_WATCHER(
            r'^execve\(\"' + re.escape(tracee.target) +
            r'", .*\) \= (?P<code>[-]?\d+)(?:$| (?P<errno>\w+) \((?P<strerror>(?:\w|\s)+)\)$)'))

        tracee.start_actual_tracee()
        watchers = parser.timeout(1).continue_until_watchers()

        reporter.handle_event(ErrorReporter.START_ACTUAL_TRACEE_EVENT,
                              **({"code": int(watchers["start"].matcher.group("code")),
                                  "strerror": watchers["start"].matcher.group("strerror")}
                                 if len(watchers) != 0 else {}))

        parser.remove_watcher(name="start")
        parser.add_watcher(name="inject",
                           watcher=StraceOutputParser.ERROR_INJECT_WATCHER(fault.syscall, fault.when))
        watchers = parser.timeout(1).continue_until_watchers()
        if len(watchers) != 0 and tracee.exitcode() == - signal.SIGSEGV:
            print(watchers["inject"].occasion, file=sys.stderr)
            print("Yahooo!", file=sys.stderr)

        reporter.unwatch()
        exit(0)


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

    def add_entry(self, fault: Fault, context: str):
        self._entries.append(dict(fault=fault, context=context))
        self.print()

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


class ErrorReporter:
    def __init__(self, program, tofile=sys.stderr):
        self.prog = program
        self.tofile = tofile
        self._tracee = None
        self._tracer = None

    def watch_tracee(self, tracee):
        self._tracee = tracee

    def watch_tracer(self, tracer):
        self._tracer = tracer

    def unwatch(self):
        self._tracee = None
        self._tracee = None

    def _terminate_and_exit(self):
        if self._tracee is not None:
            self._tracee.terminate()
        if self._tracer is not None:
            self._tracer.terminate()
        self.unwatch()
        exit(1)

    def handle_event(self, event, **kwargs):
        event(self, **kwargs)

    def _tracee_wait_for_started_event(self, success):
        if not success:
            print(self.prog + ": tracee was externally terminated: exitcode {}".
                  format(self._tracee.exitcode(blocking=True)), file=self.tofile)
            self._terminate_and_exit()

    def _tracer_started_event(self, first_line):
        if first_line is None:
            print(self.prog + ": strace doesn't respond", file=sys.stderr)
            # code = tracer.exitcode(blocking=True)
            # if code < 0:
            #    print(self.prog + ": tracee terminated with signal {}".
            #          format(signal.Signals(-code).name), file=sys.stderr)
            # else:
            #    print(self.prog + ": tracee terminated with exit status {}".
            #          format(code), file=sys.stderr)

        elif first_line == self._tracer.executable + ": Process {} attached".format(self._tracee.pid):
            return
        elif re.match(r'^cannot run strace: .*$', first_line) \
                or re.match(r'^' + re.escape(self._tracer.executable) + r': .*$', first_line):
            print(self.prog + ': ' + first_line, file=sys.stderr)

        else:
            print(self.prog + ': Unknown error', file=sys.stderr)

        self._terminate_and_exit()

    def _start_actual_tracee(self, code=None, strerror=None):
        if code is None:
            print(self.prog + ": actual tracee was not started", file=sys.stderr)
        elif code == 0:
            return
        elif code == -1:
            print(self.prog + ": cannot run tracee: {}".format(strerror), file=sys.stderr)

        self._terminate_and_exit()

    TRACEE_WAIT_FOR_STARTED_EVENT   = _tracee_wait_for_started_event
    TRACER_STARTED_EVENT            = _tracer_started_event
    START_ACTUAL_TRACEE_EVENT       = _start_actual_tracee


class StraceOutputParser:
    NON_EMPTY_LINES_PATTERN = re.compile(r'(?:^.+$\s)|(?:^.+$)', flags=re.M)

    class ERROR_INJECT_WATCHER(Watcher):
        def __init__(self, syscall, when):
            Watcher.__init__(self)
            if when <= 0:
                raise ValueError
            self._syscall = syscall
            self._when = when
            self._were = 0

        @Watcher.watcher_call
        def __call__(self, line):
            if line.startswith(self._syscall):
                self._were = self._were + 1

            return self._were == self._when

        @property
        def were(self):
            return self._were

    class REGEX_WATCHER(Watcher):
        def __init__(self, regex):
            Watcher.__init__(self)
            self._regex = re.compile(regex)
            self._matcher = None

        @Watcher.watcher_call
        def __call__(self, line):
            self._matcher = self._regex.match(line)
            return self._matcher is not None

        @property
        def matcher(self):
            return self._matcher

    def __init__(self, tracer):
        self._tracer = tracer
        self._lines = []
        self._timeout = 0
        self._watchers = {}

    def timeout(self, new_timeout):
        self._timeout = new_timeout
        return self

    def pop_line(self):
        line = self.next_line()
        if line is not None:
            self._lines.pop(0)
        return line

    def next_line(self):
        if self.has_line():
            return self._lines[0][:-1]
        self._more()
        if self.has_line():
            return self._lines[0][:-1]
        return None

    def has_line(self):
        return len(self._lines) >= 1 and self._lines[0].endswith('\n')

    def remainder(self):
        return self._lines

    # Actual time can be slightly different from that specified in timeout().
    # timeout() is necessary only if actual reading strace output will be done
    def continue_until_watchers(self):
        clock = time.perf_counter()
        old_timeout = self._timeout
        timeout_left = self._timeout
        watchers_stopped = {}
        while True:
            if self.has_line():
                watchers_stopped = {n: w for (n, w) in self._watchers.items() if w(self._lines[0][:-1])}
                if len(watchers_stopped) != 0:
                    break

            if self.has_line():
                self.pop_line()
                continue

            self._timeout = timeout_left
            self._more()

            timeout_left = old_timeout - (time.perf_counter() - clock)
            if timeout_left <= 0:
                break

        self._timeout = old_timeout
        return watchers_stopped

    def add_watcher(self, name, watcher):
        if not isinstance(watcher, Watcher):
            return

        self._watchers[name] = watcher

    def remove_watcher(self, name):
        del self._watchers[name]

    @property
    def watchers(self):
        return self._watchers

    def _more(self):
        output = StraceOutputParser.NON_EMPTY_LINES_PATTERN.findall(
            self._tracer.readbuf(timeout=self._timeout))
        if len(output) == 0:
            return
        if len(self._lines) >= 1 and not self._lines[-1].endswith('\n'):
            self._lines[-1] = self._lines[-1] + output.pop(0)
        self._lines.extend(output)


if __name__ == '__main__':
    argvHandler = ArgvHandler()

    for fault in InjectionGenerator():
        controller = ExecutionController(argvHandler, fault)
        controller.start()
        continue

    exit(0)
