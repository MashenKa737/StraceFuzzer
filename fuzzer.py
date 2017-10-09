import sys
import os
import signal
import time
import select
import argparse
import re


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

    @property
    def target(self):
        return self._args.target

    @property
    def strace_executable(self):
        return self._args.strace_executable

    @property
    def target_args(self):
        return self._args.args


# should be linked with other part of project in any way
class InjectionGenerator:
    def __init__(self):
        pass

    def __iter__(self):
        return self

    def __next__(self):
        return "fault=open:error=ENOENT:when=4"


class AbstractPipeProcess:
    def __init__(self):
        self.pid = None
        self._exitcode = None
        (self._r, self._w) = None, None

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

    @staticmethod
    def _say_parent_was_killed():
        print("fuzzer: main program was terminated", file=sys.stderr)


# the bicycle for subprocess.Popen
class TracerProcess(AbstractPipeProcess):
    def __init__(self, pid, fault):
        AbstractPipeProcess.__init__(self)
        self._tracee_pid = pid
        self._fault = fault
        self.err = None
        self.executable = 'strace'
        self.args = "-p", str(self._tracee_pid), "-e", self._fault

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
                print("fuzzer: cannot run strace: {}".format(exc.strerror), file=sys.stderr)
            except BrokenPipeError:
                AbstractPipeProcess._say_parent_was_killed()
            exit(1)


class TraceeProcess(AbstractPipeProcess):
    def __init__(self, target, args):
        AbstractPipeProcess.__init__(self)
        del (self._w, self._r)
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
            AbstractPipeProcess._say_parent_was_killed()
        except OSError as exc:
            try:
                os.write(self._wwait, exc.errno.to_bytes(sys.getsizeof(exc.errno), byteorder=sys.byteorder))
            except BrokenPipeError:
                AbstractPipeProcess._say_parent_was_killed()

        os.close(self._wwait)
        exit(1)

    # call it only after start method and only once
    # if returns false, calling any method using pipe (e. g. execution_error_msg) is prohibited
    def wait_for_started(self):
        # It cannot be blocked in any way and might execute relatively quickly
        msg = os.read(self._rwait, len(b'wait'))
        return msg == b'wait'

    # TODO this function can be useful for determination of whether tracee cannot be executed
    # returns error message, if calling os.exec by tracee was unsuccessful
    # returns None, if os.exec was not called yet
    # return "", if os.exec was called successfully
    # if returns not None, calling once again is prohibited
    def execution_error_msg(self):
        msg = ""
        if os.get_blocking(self._rwait):
            os.set_blocking(self._rwait, False)
        try:
            errno_bytes = os.read(self._rwait, sys.getsizeof(int()))
        except BlockingIOError:
            return None
        if len(errno_bytes) != 0:
            errno = int.from_bytes(errno_bytes, byteorder=sys.byteorder)
            msg = "fuzzer: cannot run tracee: {}".format(os.strerror(errno))
        return msg

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
        reporter = ErrorReporter(tofile=sys.stderr)

        tracee = TraceeProcess(self.args.target, self.args.target_args)
        reporter.watch_tracee(tracee)

        tracee.start()
        reporter.handle_event(ErrorReporter.TRACEE_WAIT_FOR_STARTED_EVENT,
                              success=tracee.wait_for_started())

        tracer = TracerProcess(pid=tracee.pid, fault=self.fault)
        tracer.set_executable(self.args.strace_executable)
        parser = StraceOutputParser(tracer)
        reporter.watch_tracer(tracer)

        tracer.start()
        reporter.handle_event(ErrorReporter.TRACER_STARTED_EVENT,
                              first_line=parser.timeout(0.5).pop_line())

        parser.add_watcher(name="execve", watcher=StraceOutputParser.REGEX_WATCHER("^execve"))
        tracee.start_actual_tracee()
        watchers = parser.continue_until_watchers()
        print(watchers["execve"].occasion, file=sys.stderr)

        reporter.unwatch()
        exit(0)


class ErrorReporter:
    def __init__(self, tofile=sys.stderr):
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
            print("fuzzer: tracee was externally terminated: exitcode {}".
                  format(self._tracee.exitcode(blocking=True)), file=self.tofile)
            self._terminate_and_exit()

    def _tracer_started_event(self, first_line):
        return

    TRACEE_WAIT_FOR_STARTED_EVENT = _tracee_wait_for_started_event
    TRACER_STARTED_EVENT = _tracer_started_event


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

        @Watcher.watcher_call
        def __call__(self, line):
            return self._regex.match(line)

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
            print(line, file=sys.stderr)
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
        assert len(self._lines) <= 1 or self._lines[0].endswith('\n')
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

        tracee = TraceeProcess(argvHandler.target(), argvHandler.target_args())
        tracee.start()
        success = tracee.wait_for_started()
        if not success:
            print("fuzzer: tracee was externally terminated: exitcode {}".
                  format(tracee.exitcode()), file=sys.stderr)
            exit(1)

        tracer = TracerProcess(pid=tracee.pid, fault=fault)
        tracer.set_executable(argvHandler.strace_executable())
        tracer.start()
        strace_stderr = tracer.readlines(timeout=0.5)
        for line in strace_stderr:
            print(line, file=sys.stderr, end='')

        if len(strace_stderr) == 1 and strace_stderr[0].startswith("fuzzer: cannot run strace:"):
            print(strace_stderr[0], file=sys.stderr, end='')
            exit(1)

        elif tracer.executable + ": Process {} attached\n".format(tracee.pid) in \
                strace_stderr:
            pass
        else:
            # TODO add more error handling
            print("fuzzer: some error occured:\ntracee exitcode: {}\ntracer exitcode: {}"
                  .format(tracee.exitcode(), tracer.exitcode(), file=sys.stderr))

            tracer.terminate()
            tracee.terminate()
            exit(1)

        success = tracee.start_actual_tracee()
        if not success:
            print("fuzzer: tracee was externally terminated: exitcode {}".
                  format(tracee.exitcode()), file=sys.stderr)
            exit(1)

        # TODO the main branch of further development
        strace_stderr = tracer.readlines(timeout=1)
        for line in strace_stderr:
            print(line, file=sys.stderr, end='')

        time.sleep(1)
        if tracee.exitcode() == - signal.SIGSEGV:
            print("Yahoooo!")
            exit(0)

        tracer.terminate()
        tracee.terminate()
        exit(0)

    # end of "for fault in InjectionGenerator():"

    exit(0)
