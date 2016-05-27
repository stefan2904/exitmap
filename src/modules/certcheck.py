#!/usr/bin/env python2

"""
Check TLS certificates for a given list of sites over all Tor exit nodes.
The purpose of this script is to find exit nodes who do MITM
by breaking the TLS connecting (SSLstrip) by using their own certificate.
"""

import sys
import httplib
import collections
import logging
import util
import ssl
import csv
import OpenSSL

log = logging.getLogger(__name__)

# destinations = [("www.google.com", 443)]
# DOMAIN, PORT = destinations[0]

PORT = 443


def handleCertificateError(err, domain, exit_url):
    """

    """

    tmp = 'Domain: ' + str(domain) + '\n'
    tmp += 'Exit url: ' + str(exit_url) + '\n'
    tmp += 'Error: ' + str(err) + '\n'

    try:
        asn1cert = ssl.get_server_certificate((domain, PORT))
        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, asn1cert)

        tmp += 'Digest: ' + str(x509.digest('sha256')) + '\n'
    except Exception as err:
        tmp += 'Exception: ' + str(err) + '\n'

    print(tmp + '\n')


def readCertOfPage(page, exit_url):
    """
    Read TLS certificate for the given page.
    Handle certificate errors accordingly.
    """

    domain = page['webpage']
    HTTP_HEADERS = [
        ('Host',
         domain),
        ('User-Agent',
         'Mozilla/5.0 (Windows NT 6.1; rv:38.0) '
         'Gecko/20100101 Firefox/38.0'),
        ('Accept',
         'text/html,application/xhtml+xml,'
         'application/xml;q=0.9,*/*;q=0.8'),
        ('Accept-Language',
         'en-US,en;q=0.5'),
        ('Accept-Encoding',
         'gzip, deflate'),
        ('Content-Length',
         '0')]

    try:
        conn = httplib.HTTPSConnection(domain, PORT)
        conn.request(
            'GET', '/', headers=collections.OrderedDict(HTTP_HEADERS))
        # response = conn.getresponse()

    except ssl.CertificateError as err:
        handleCertificateError(err, domain, exit_url)

    except Exception as err:
        pass


def readCert(exit_fpr):
    """
    Read TLS certificates for all domains in sitelist.
    """

    sitelist = 'top-1m.csv'

    exit_url = util.exiturl(exit_fpr)
    log.debug('Probing exit relay \"%s\".' % exit_url)

    with open(sitelist) as csvfile:
        for page in csv.DictReader(csvfile, delimiter=','):
            readCertOfPage(page, exit_url)


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    Entry point for exitmap.
    """

    run_python_over_tor(readCert, exit_desc.fingerprint)


if __name__ == '__main__':
    """
    Entry point running this script directly on the commandline.
    """

    readCert('bogus-exitmap')
    sys.exit(0)
