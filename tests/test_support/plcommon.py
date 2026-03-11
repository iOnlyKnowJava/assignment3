# Copyright (C) 2022 Carnegie Mellon University
# Copyright (C) 2025 University of Texas at Austin
#
# No part of the project may be copied and/or distributed without the express
# permission of the course staff.

import sys
from subprocess import PIPE, STDOUT, Popen


def check_output(args, shouldPrint=True):
    return check_both(args, shouldPrint)[0]


def check_both(args, shouldPrint=True, check=True):
    out = ""
    p = Popen(args, shell=True, stdout=PIPE, stderr=STDOUT)
    assert p.stdout is not None
    while True:
        line = p.stdout.readline()
        if not line:
            break
        line = line.decode("utf-8")
        if shouldPrint:
            sys.stdout.write(line)
        out += line
    rc = p.wait()
    out = (out, "")
    out = (out, rc)
    if check and rc != 0:
        raise Exception(
            f"subprocess.CalledProcessError: Command '{args}' "
            f"returned non-zero exit status: {rc}"
        )
    return out
