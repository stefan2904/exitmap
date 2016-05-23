#!/usr/bin/env python2

"""
Check certificate.
"""

import sys
import os
import StringIO
import httplib
import collections
import logging
import util
import ssl
import csv
import OpenSSL

log = logging.getLogger(__name__)

#destinations = [("www.google.com", 443)]
#DOMAIN, PORT = destinations[0]

PORT = 443


# Mimic Tor Browser's request headers


def readcert(exit_fpr):
    """
    Read ssl certificate.
    """

    exit_url = util.exiturl(exit_fpr)
    log.debug("Probing exit relay \"%s\"." % exit_url)
    print(exit_url)

    with open('top-1m.csv') as csvfile:
        pagereader = csv.DictReader(csvfile, delimiter=',')
        for page in pagereader:
            DOMAIN = page['webpage']
            HTTP_HEADERS = [
                ("Host",
                 DOMAIN),
                ("User-Agent",
                 "Mozilla/5.0 (Windows NT 6.1; rv:38.0) "
                 "Gecko/20100101 Firefox/38.0"),
                ("Accept",
                 "text/html,application/xhtml+xml,"
                 "application/xml;q=0.9,*/*;q=0.8"),
                ("Accept-Language",
                 "en-US,en;q=0.5"),
                ("Accept-Encoding",
                 "gzip, deflate"),
                ("Content-Length",
                 "0")]
            try:
                conn = httplib.HTTPSConnection(DOMAIN, PORT)
                conn.request(
                    "GET", "/", headers=collections.OrderedDict(HTTP_HEADERS))
                response = conn.getresponse()
            except ssl.CertificateError as err:
                print("\n")
                print(DOMAIN)
                print(exit_url)
                asn1cert = ssl.get_server_certificate((DOMAIN, PORT))
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, asn1cert)
                print(x509.digest("sha256"))
                #print(err)
                #print(err.__class__.__name__)
                print("\n")
            except Exception as err:
               pass
            mysock = None


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    Check if exit relay sees a CloudFlare CAPTCHA.
    """

    run_python_over_tor(readcert, exit_desc.fingerprint)


if __name__ == "__main__":
    readcert("bogus-fingerprint")
    sys.exit(0)
