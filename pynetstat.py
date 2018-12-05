"""
capture output of netstat applying a supplied expression
to each line and if matching print out match
"""
import subprocess
import sys
import re
from time import sleep
from datetime import datetime
import ctypes
import os
from prettytable import PrettyTable, PLAIN_COLUMNS


class NetStatData(object):

    pid_lookup = {}

    def __init__(self, fields_):
        self.proto = fields_[0]
        self.local = fields_[1]
        self.foreign = fields_[2]
        self.state = fields_[3] if len(fields_) == 5 else " " * 16
        self.pid = int(fields_[4]) if len(fields_) == 5 else int(fields_[3])
        self.no_state = not len(fields_) == 5
        if self.pid not in NetStatData.pid_lookup:
            self.exe = get_exe_from_pid(self.pid)
            NetStatData.pid_lookup[self.pid] = self.exe
        else:
            self.exe = NetStatData.pid_lookup[self.pid]

    def to_table_row(self):
        return [self.proto, self.local, self.foreign, self.state, self.pid, self.exe]


class _CursorInfo(ctypes.Structure):
    _fields_ = [("size", ctypes.c_int),
                ("visible", ctypes.c_byte)]


class _Coord(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short),
                ("Y", ctypes.c_short)]


def wait(secs):
    """
    countdown secs, printing the time left to the console
    \b = posix back key
    """
    fmt = "{0: <%d}" % len(str(secs))
    o = ""
    while secs > 0:
        o = fmt.format(secs)
        sys.stdout.write(o)
        sys.stdout.write('\b' * len(o))
        sys.stdout.flush()
        try:
            sleep(1)
        except KeyboardInterrupt:
            sys.stdout.write(" " * len(o))
            sys.stdout.write('\b' * len(o))
            sys.stdout.flush()
            raise KeyboardInterrupt
        secs -= 1
    sys.stdout.write(" " * len(o))
    sys.stdout.write('\b' * len(o))
    sys.stdout.flush()


def hide_cursor():
    if os.name == 'nt':
        ci = _CursorInfo()
        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        ctypes.windll.kernel32.GetConsoleCursorInfo(handle, ctypes.byref(ci))
        ci.visible = False
        ctypes.windll.kernel32.SetConsoleCursorInfo(handle, ctypes.byref(ci))
    elif os.name == 'posix':
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()


def show_cursor():
    if os.name == 'nt':
        ci = _CursorInfo()
        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        ctypes.windll.kernel32.GetConsoleCursorInfo(handle, ctypes.byref(ci))
        ci.visible = True
        ctypes.windll.kernel32.SetConsoleCursorInfo(handle, ctypes.byref(ci))
    elif os.name == 'posix':
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()


def get_exe_from_pid(pid: int):
    o = subprocess.getoutput('tasklist /FI "PID eq %d" /FO CSV /NH' % pid)
    o = o.strip().split(",")
    if len(o) > 2:
        return o[0].strip('"')
    return None


def get_pids_from_exe(exe_: str) -> dict:
    """produce a lookup table of pid to exe name
    """
    o = subprocess.getoutput('tasklist /FO CSV /NH /FI "IMAGENAME eq %s"' % exe_)
    back = {}
    for v in o.split('\n'):
        v = v.split(",")
        if len(v) > 2:
            back[int(v[1].strip('"'))] = v[0].strip('"')
    return back


def from_args():
    nsargs_ = "-ano"
    pattern_ = ".*"
    forever_ = False
    timeout_ = 10
    exe_ = None
    for arg in sys.argv[1:]:
        if arg.startswith("-exe:"):
            exe_ = arg[5:]
            if not exe_.endswith(".exe") and not exe_.endswith("*"):
                exe_ += "*"
            continue
        if arg.startswith("-l"):
            s1 = arg.find(":")
            if s1 > -1:
                timeout_ = int(arg[s1+1:])
            forever_ = True
            continue
        # if arg.startswith("-"):
        #     nsargs_ = arg
        #     continue
        pattern_ = arg
    return nsargs_, pattern_, forever_, timeout_, exe_


def natural_sort_key(s, _nsre=re.compile('([0-9]+)')):
    if isinstance(s, (tuple, list, set)):
        s = s[0]
    return [int(text) if text.isdigit() else text.lower()
            for text in _nsre.split(s)]


if __name__ == '__main__':

    if len(sys.argv) == 1:
        fn = os.path.basename(__file__)
        print("core-team\\%s v1.1\n" % fn)
        print("usage: %s expression [-l/-l:10/-exe:execuable]" % fn)
        table = PrettyTable()
        table.field_names = ["arg", "help"]
        table.set_style(PLAIN_COLUMNS)
        table.align["arg"] = table.align["help"] = "l"
        table.add_row(["expression", "regex to match against netstat output (case insensitive)"])
        table.add_row(["-l (ell)", "keep on doing check, waiting 10 seconds between each call"])
        table.add_row(["-l:N", "keep on doing check, waiting N seconds between each call"])
        table.add_row(["-exe:Name", "find all ports attached to exe name (basic wildcard usage accepted"])
        print(table.get_string(header=False, padding_width=0, left_padding_width=0, right_padding_width=4))
        print("\nexamples")
        print("'pynetstat estab -exe:pred*'\twill display all the ESTABLISHED connections for predictor.exe")
        print("'pynetstat 9104\\s+established'\twill diplay any ports listening on 9104 that have been ESTABLISHED")
        sys.exit(666)

    nsargs, pattern, forever, timeout, exe = from_args()

    # user wants to lookup via exe name
    # find the exes pids - there may be more than one running 
    NetStatData.pid_lookup = get_pids_from_exe(exe) if exe is not None else {}
    if exe:
        if len(NetStatData.pid_lookup) == 0:
            print("can't find running exe '%s'" % exe)
            sys.exit(666)
        # now we can use a pattern to match against the pid of the exe
        # i.e. .*(pid|otherpid) - using '\spid\b' to just match on pid at end of line
        pattern = pattern + ".*" if not pattern.endswith(".*") else pattern
        pattern_pids = "".join(map(lambda i: "\\s%s$|" % i, NetStatData.pid_lookup.keys()))
        pattern += "(" + pattern_pids[:-1] + ")"
    
    # enum each line of netstat trying to match the expression we have
    title = None
    in_hdr = True
    table = PrettyTable()
    table.field_names = ["Proto", "Local", "Foreign", "State", "PID", "EXE"]
    table.align["PID"] = "r"
    table.align["Proto"] = table.align["EXE"] = table.align["Local"] = \
        table.align["Foreign"] = table.align["State"] = "l"
    table.set_style(PLAIN_COLUMNS)
    table.padding_width = 0
    try:
        hide_cursor()
        while True:
            lines = subprocess.getoutput("netstat %s" % nsargs)
            if lines is None:
                break
            found = 0
            # go line by line through the data from netstat
            # if theres a header print it out
            for idx, line in enumerate(lines.split('\n')):
                line = line.strip()
                if len(line) > 1:
                    if in_hdr and line.startswith("Proto"):
                        title = line
                        in_hdr = False
                        continue
                    elif not in_hdr:
                        if re.search(pattern, line, flags=re.IGNORECASE):
                            fields = re.split("\\s+", line)
                            if len(fields) < 2:
                                continue
                            table.add_row(NetStatData(fields).to_table_row())
                            found += 1

            tm = datetime.now().strftime("%H:%M:%S")
            if found > 0:
                print("@ %s, found %d %s\n" % (tm, found, "matches" if found > 1 else "match"))
                hdr = table.get_string(
                    title="netstat %s" % nsargs, sortby="EXE", sort_key=natural_sort_key,
                    left_padding_width=0, right_padding_width=3
                )
                # HACK: print a seperator row between the header and the data
                idx = hdr.find('\n')
                nxt_idx = hdr.find('\n', idx + 1)
                tit = "=" * ((nxt_idx - idx) - 9)
                hdrb = hdr[:idx]
                body = hdr[idx + 1:]
                print(hdrb)
                print(tit)
                print(body)
            else:
                print("@ %s, found nothing" % tm)

            if not forever:
                break
            table.clear_rows()
            wait(timeout)
    except KeyboardInterrupt:
        sys.exit(0)
    finally:
        show_cursor()
