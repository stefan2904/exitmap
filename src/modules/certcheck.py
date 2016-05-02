#!/usr/bin/env python2

"""
Check certificate.
"""

import sys
import StringIO
import httplib
import collections
import logging
import util
import OpenSSL

log = logging.getLogger(__name__)

destinations = [("www.google.com", 443)]
DOMAIN, PORT = destinations[0]


# Mimic Tor Browser's request headers

HTTP_HEADERS = [("Host", DOMAIN),
                ("User-Agent", "Mozilla/5.0 (Windows NT 6.1; rv:38.0) "
                               "Gecko/20100101 Firefox/38.0"),
                ("Accept", "text/html,application/xhtml+xml,"
                           "application/xml;q=0.9,*/*;q=0.8"),
                ("Accept-Language", "en-US,en;q=0.5"),
                ("Accept-Encoding", "gzip, deflate"),
                ("Content-Length", "0")]



def readcert(exit_fpr):
    """
    Read ssl certificate.
    """

    exit_url = util.exiturl(exit_fpr)
    log.debug("Probing exit relay \"%s\"." % exit_url)

    conn = httplib.HTTPSConnection(DOMAIN, PORT, strict=False)
    conn.request("GET", "/", headers=collections.OrderedDict(HTTP_HEADERS))
    try:
        response = conn.getresponse()
    except Exception as err:
        log.warning("urlopen() over %s says: %s" % (exit_url, err))
        return
    asn1cert = conn.sock.getpeercert(True)
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, asn1cert)
    print(x509.get_subject().get_components())


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    Check if exit relay sees a CloudFlare CAPTCHA.
    """

    run_python_over_tor(readcert, exit_desc.fingerprint)


if __name__ == "__main__":
    readcert("bogus-fingerprint")
    sys.exit(0)
