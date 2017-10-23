import re
import time


class Watcher:
    # used as decorator for functions __call__ in all Watcher's successors
    class watcher_call:
        def __init__(self):
            pass

        def __call__(self, call):
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

    @watcher_call()
    def __call__(self, line):
        return True

    @property
    def occasion(self):
        return self._occasion


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

        @Watcher.watcher_call()
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

        @Watcher.watcher_call()
        def __call__(self, line):
            self._matcher = self._regex.match(line)
            return self._matcher is not None

        @property
        def matcher(self):
            return self._matcher

    class REMEMBER_SYSCALLS_WATCHER(Watcher):
        def __init__(self, max_syscalls=None):
            Watcher.__init__(self)
            self._max_syscalls = max_syscalls
            self._list_syscalls = []
            self._syscallPattern = re.compile(r'(?P<syscall>\w+)\(.*')

        @Watcher.watcher_call()
        def __call__(self, line):
            matcher = self._syscallPattern.match(line)
            if matcher is None:
                return True
            syscall = matcher.group("syscall")
            self._list_syscalls.append(syscall)
            if self._max_syscalls is not None and len(self._list_syscalls) == self._max_syscalls:
                return True
            return False

        @property
        def list_syscalls(self):
            return self._list_syscalls

        @property
        def max_syscalls(self):
            return self._max_syscalls

    def __init__(self, tracer):
        self._tracer = tracer
        self._lines = []
        self._timeout = 0
        self._watchers = {}
        self.maximal_timestep = 0

    def timeout(self, new_timeout):
        self._timeout = new_timeout
        return self

    def set_maximal_timestep(self, new_tmstp):
        self.maximal_timestep = new_tmstp

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
        timeout_left = self._timeout
        clock = time.perf_counter()
        while True:
            timeout_left = min(timeout_left, self.maximal_timestep)
            output = StraceOutputParser.NON_EMPTY_LINES_PATTERN.findall(
                self._tracer.readbuf(timeout=timeout_left))

            timeout_left = self._timeout - (time.perf_counter() - clock)

            if len(output) != 0:
                new_line = len(output) > 1 or output[0].endswith('\n')
                if len(self._lines) >= 1 and not self._lines[-1].endswith('\n'):
                    self._lines[-1] = self._lines[-1] + output.pop(0)
                self._lines.extend(output)
                if new_line:
                    return

            if timeout_left <= 0:
                return
