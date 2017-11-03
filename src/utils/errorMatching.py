import json
import re
import sys
import gzip


class SyscallErrorMatchingGenerator:
    def __init__(self, man_path="/usr/share/man"):
        """
        :param man_path: string performs the absolute path to man
        """
        self.man_path = man_path
        self.syscall = list()
        self.patternCall = re.compile(r"\\fB(?P<syscall>\w+)\\fP\(2\)")
        self.patternError = re.compile(r"\.B (?P<error>E\w+)")
        self.patternLink = re.compile(r"\.so (?P<link>man[23]/\w+\.[23])")
        self.error_dict = dict()
        self.no_errors_list = list()

    def dump_no_error_list(self, file_name):
        """
        dumped names of all man2 pages containing no error
        or not fitting the heuristic regular expression
        :param file_name: name of bash file to be generated
        
        """
        with open(file_name, 'w') as fout:
            fout.write("#!/bin/bash\n")
            for fname in self.no_errors_list:
                fout.write("echo {}:\n".format(fname))
                fout.write("cat {}\n".format(fname))
                fout.write("echo _________________________\n")

    def find_error_r(self, man_page):
        """
        looks for errors in man page
        if the file contains link "\.so", parses the link

        :param man_page: name of  man page .gz file describing the syscall
        :return: set containing errors for syscall
        """

        with gzip.open(man_page) as f:
            error = set()

            lmatch = self.patternLink.match(f.readline().decode("utf-8"))
            if lmatch is not None:
                link = lmatch.group("link")
                error = self.find_error_r(self.man_path + "/{}.gz".format(link))
                return error
            else:
                for line in f.readlines():
                    m = self.patternError.match(line.decode("utf-8"))
                    if m is not None:
                        err = m.group("error")
                        error.add(err)

            return error

    def generate(self):
        with gzip.open(self.man_path + "/man2/syscalls.2.gz", "r") as fin:
            for line in fin.readlines():
                m = self.patternCall.match(line.decode("utf-8"))
                if m is not None:
                    call = m.group("syscall")
                    self.syscall.append(call)
        
        for name in self.syscall:
            try:
                error = self.find_error_r(self.man_path + "/man2/{}.2.gz".format(name))
                if len(error) == 0:
                    self.no_errors_list.append(self.man_path + "/man2/{}.2.gz".format(name))
                else:
                    self.error_dict[name] = list(error)
            except IOError:
                print("file not found: {}".format(name), file=sys.stderr)

    def print(self, fileout):
        """
        print dictionary to the file in json format

        :param fileout: name of json file
        """
        with open(fileout, "w", encoding="utf-8") as file:
            json.dump(self.error_dict, file)


if __name__ == '__main__':
    error_dict = SyscallErrorMatchingGenerator()
    error_dict.generate()
    error_dict.print("syscall_error.json")
