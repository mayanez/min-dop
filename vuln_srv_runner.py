"""VulnSrvAPI Runner
Ensures Complete Code Coverage for "vuln_srv"

Usage:
    runner.py --help
    runner.py [--gdb] [--port=<num>]

"""

import sys
import subprocess
import vuln_srv
import logging

from docopt import docopt
from vuln_srv import VulnSrvAPI, complete_code_coverage

PORT = 1111


def run(gdb, port):
    vuln_srv_api = VulnSrvAPI(port, gdb)
    complete_code_coverage(vuln_srv_api)


logging.basicConfig()
logging.getLogger(vuln_srv.__name__).setLevel(logging.DEBUG)

if __name__ == '__main__':

    args = docopt(__doc__)

    port = PORT

    if args['--port'] is not None:
        port = int(args['--port'])

    gdb = args['--gdb']

    if gdb:
        # To preprocess with GDB we need to run within GDB's Python Interpreter
        subprocess.call([
            'gdb', '-q', '-ex',
            'python import os,sys; \
        sys.path.append(os.getcwd()); import vuln_srv_runner; from vuln_srv_runner import run; run(%s, %s); \
        sys.exit(0)' % (gdb, port)
        ])
    else:
        run(gdb, port)
