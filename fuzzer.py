import sys
import os
import multiprocessing
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


# the bicycle for subprocess.Popen
class TracerProcess:
    def __init__(self, pid, fault):
        self._tracee_pid = pid
        self._fault = fault
        self.exitcode = None
        self.pid = None
        (self._r, self._w) = None, None
        self.err = None

        # TODO temporary hardcode
        self.args = "/home/ilya/strace/bin/strace", "-p",\
                    str(self._tracee_pid), "-e", self._fault

    def start(self):
        (self._r, self._w) = os.pipe2(os.O_NONBLOCK)
        self.pid = os.fork()
        if self.pid == 0:
            self._execute_tracer()

        os.close(self._w)
        self.err = os.fdopen(self._r, mode="rt")

    def readlines(self, timeout):
        # TODO
        # current implementation uses busy loop
        # further development might abandon this solution
        # 'select' module will probably be used
        if self.exitcode is not None:
            return []

        lines = []
        clock = time.perf_counter()
        while time.perf_counter() - clock < timeout:
            time.sleep(1)
            lines.extend(itertools.takewhile(lambda line: line != "", self.err.readlines()))
            self._update_exitcode()
            if self.exitcode is not None:
                break

        return lines

    def terminate(self):
        self._update_exitcode()
        if self.exitcode is None:
            os.kill(self.pid, signal.SIGTERM)
            self.err.close()
            self._update_exitcode()

    def _update_exitcode(self):
        if self.exitcode is not None:
            return

        (pid, status) = os.waitpid(self.pid, os.WNOHANG)
        if pid == 0:
            return

        assert pid == self.pid,\
            "pid returned by successful waitpid doesn't equal to child's pid"

        if os.WIFSIGNALED(status):
            self.exitcode = - os.WTERMSIG(status)
        elif os.WIFEXITED(status):
            self.exitcode = os.WEXITSTATUS(status)

    def _execute_tracer(self):
        os.close(self._r)
        try:
            os.dup2(self._w, sys.stderr.fileno())

            # TODO temporary hardcode
            os.execvp("/home/ilya/strace/bin/strace", self.args)
        except OSError as exc:
            # It will be send through pipe, if dup2 call was successful
            print("fuzzer: cannot run strace: {}".format(exc.strerror), file=sys.stderr)
            exit(1)


def execute_tracee(conn_start, target):
    try:
        msg = conn_start.recv()
    except EOFError:  # parent process is killed
        exit(1)
    else:
        if msg == "start":
            os.execl("/home/ilya/StraceFuzzer/test/test1", "/home/ilya/StraceFuzzer/test/test1")

    exit(1)


if __name__ == '__main__':
    argvHandler = ArgvHandler()
    if argvHandler.target is None:
        exit(1)

    for fault in InjectionGenerator():
        (r, w) = multiprocessing.Pipe(duplex=False)
        tracee = multiprocessing.Process(target=execute_tracee, args=(r, argvHandler.target))
        tracee.start()

        try:
            tracer = TracerProcess(pid=tracee.pid, fault=fault)
            tracer.start()

        except OSError as exc:
            print("fuzzer: cannot run strace: {}".format(exc.strerror))
            exit(1)

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
                  .format(tracee.exitcode, tracer.exitcode, file=sys.stderr))

            tracer.terminate()
            tracee.terminate()
            exit(1)

        try:
            w.send("start")
        except BrokenPipeError:
            print("fuzzer: tracee was externally terminated: exitcode {}".
                  format(tracee.exitcode), file=sys.stderr)

        # TODO the main branch of further development
        strace_stderr = tracer.readlines(timeout=1)
        for line in strace_stderr:
            print(line, file=sys.stderr, end='')

        if tracee.exitcode == - signal.SIGSEGV:
            print("Yahoooo!")
            exit(0)

        tracer.terminate()
        tracee.terminate()
        exit(0)

    # end of "for fault in InjectionGenerator():"

    exit(0)
