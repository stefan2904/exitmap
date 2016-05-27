#!/usr/bin/env python2

"""
Check TLS certificates for a given list of sites over all Tor exit nodes.
The purpose of this script is to find exit nodes who do MITM
by breaking the TLS connecting (SSLstrip) by using their own certificate.
"""

import sys
import certutil

# destinations = [("www.google.com", 443)]
# DOMAIN, PORT = destinations[0]

# moved cert checking code to ./src/certutil.py


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    Entry point for exitmap.
    """

    run_python_over_tor(certutil.readCert, exit_desc.fingerprint)


if __name__ == '__main__':
    """
    Entry point running this script directly on the commandline.
    """

    certutil.readCert('bogus-exitmap')
    sys.exit(0)
