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
