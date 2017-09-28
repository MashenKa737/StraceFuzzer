import sys
import os
import signal
import time
import itertools


# TODO add processing arguments
class ArgvHandler:
    def __init__(self):
        if len(sys.argv) != 2:
            self.target = None
        else:
            self.target = sys.argv[1]
            self.args_target = []

    def target(self):
        return self.target


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

    def exitcode(self):
        self._update_exitcode()
        return self._exitcode

    def _update_exitcode(self):
        if self._exitcode is not None:
            return

        (pid, status) = os.waitpid(self.pid, os.WNOHANG)
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

        # TODO temporary hardcode
        self.args = "/home/ilya/strace/bin/strace", "-p",\
                    str(self._tracee_pid), "-e", self._fault

    # call it only once
    # override
    def start(self):
        # TODO make output riderection blocking, use select to read strace stderr
        (self._r, self._w) = os.pipe2(os.O_NONBLOCK)
        self.pid = os.fork()
        if self.pid == 0:
            self._execute_tracer()

        os.close(self._w)
        os.set_inheritable(self._r, False)
        self.err = os.fdopen(self._r, mode="rt")

    def readlines(self, timeout):
        # TODO
        # current implementation uses busy loop
        # further development might abandon this solution
        # 'select' module will probably be used

        # we are checking _exitcode, not exitcode() as there can be some useful
        # information in pipe
        if self._exitcode is not None:
            return []

        lines = []
        clock = time.perf_counter()
        while time.perf_counter() - clock < timeout:
            time.sleep(1)
            lines.extend(itertools.takewhile(lambda line: line != "", self.err.readlines()))
            if self.exitcode() is not None:
                break

        return lines

    # override
    def terminate(self):
        if self.exitcode() is None:
            os.kill(self.pid, signal.SIGTERM)
            self.err.close()
            self.err = None
            self._update_exitcode()

    def _execute_tracer(self):
        os.close(self._r)
        try:
            os.dup2(self._w, sys.stderr.fileno())
            os.close(self._w)

            # TODO temporary hardcode
            os.execvp("/home/ilya/strace/bin/strace", self.args)
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
        self.target = "/home/ilya/StraceFuzzer/test/test1"
        self.args = "/home/ilya/StraceFuzzer/test/test1"
        self.write = None
        self.read = None

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
                os.execl(self.target, self.args)

        except BrokenPipeError:
            os.close(self._rstart)
            AbstractPipeProcess._say_parent_was_killed()
        except OSError as exc:
            try:
                os.write(self._wwait, exc.errno.to_bytes(sys.getsizeof(msg), byteorder=sys.byteorder))
            except BrokenPipeError:
                AbstractPipeProcess._say_parent_was_killed()

        os.close(self._wwait)
        exit(1)

    # call it only after start method and only once
    # if returns false, calling any method using pipe (e. g. execution_error_msg) is prohibited
    def wait_for_started(self):
        # It cannot be blocked in any way and might execute relatively quickly
        msg = os.read(self._rwait, len(b'wait'))
        if msg == b'wait':
            return True
        else:
            os.close(self._rwait)
            os.close(self._wstart)
            return False

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
        os.close(self._rwait)
        return msg

    # call it only once
    def start_actual_tracee(self):
        success = True
        try:
            os.write(self._wstart, b'start')
        except BrokenPipeError:
            success = False
        os.close(self._wstart)
        return success

    # override
    def terminate(self):
        if self.exitcode() is None:
            os.kill(self.pid, signal.SIGTERM)
            self._update_exitcode()


if __name__ == '__main__':
    argvHandler = ArgvHandler()
    if argvHandler.target is None:
        exit(1)

    for fault in InjectionGenerator():
        tracee = TraceeProcess(argvHandler.target, argvHandler.args_target)
        tracee.start()
        success = tracee.wait_for_started()
        if not success:
            print("fuzzer: tracee was externally terminated: exitcode {}".
                  format(tracee.exitcode()), file=sys.stderr)
            exit(1)

        tracer = TracerProcess(pid=tracee.pid, fault=fault)
        tracer.start()
        strace_stderr = tracer.readlines(timeout=1)

        if len(strace_stderr) == 1 and strace_stderr[0].startswith("fuzzer: cannot run strace:"):
            print(strace_stderr[0], file=sys.stderr, end='')
            exit(1)

        # TODO temporary hardcode
        elif "/home/ilya/strace/bin/strace: Process {} attached\n".format(tracee.pid) in \
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

        if tracee.exitcode() == - signal.SIGSEGV:
            print("Yahoooo!")
            exit(0)

        tracer.terminate()
        tracee.terminate()
        exit(0)

    # end of "for fault in InjectionGenerator():"

    exit(0)
