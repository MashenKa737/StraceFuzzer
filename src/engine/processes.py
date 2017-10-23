import os
import sys
import time
import select
import signal


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
    def __init__(self, pid, args, program):
        AbstractPipeProcess.__init__(self, program)
        (self._r, self._w) = None, None
        self._tracee_pid = pid
        self._strace_args = args
        self.err = None
        self.executable = 'strace'
        self.args = None

    # call it only once
    # override
    def start(self):
        # Blocking mode of pipe is used in tracer process in order to guarantee
        # that there is no data loss of strace output, though it may be slower
        # non-blocking mode of pipe is used in parent process
        # for convenient usage of self.err.read().
        # Otherwise, we will have to use only low-level os.read
        self.args = "-p", str(self._tracee_pid), *self._strace_args
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

    def set_tracee_pid(self, pid: int):
        self._tracee_pid = pid

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
            os.execl(self.executable, self.executable, *self.args)
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
                os.execl(self.target, self.target, *self.args)

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
