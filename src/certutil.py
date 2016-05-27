#!/usr/bin/env python2

"""
Check TLS certificates for a given list of sites over all Tor exit nodes.
The purpose of this script is to find exit nodes who do MITM
by breaking the TLS connecting (SSLstrip) by using their own certificate.
"""

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

PORT = httplib.HTTPS_PORT  # 443


def logCertError(domain, exitnode, error, fingerprint, exception):
    if exception is None:
        status = 'Fingerprint: %s' % fingerprint
    else:
        status = 'Exception:   %s' % exception

    # TODO: log domain / exitnode / error / fingerprint to DB

    print('''
        Domain:      %s
        Exitnode:    %s
        Error:       %s
        %s
        '''
          % (domain, exitnode, error, status))


def handleCertError(err, domain, exitnode, certErrorLogger):
    domain = str(domain)
    exitnode = str(exitnode)
    error = str(err)
    fingerprint = None
    exception = None

    try:
        asn1Cert = ssl.get_server_certificate((domain, PORT))
        x509Cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, asn1Cert)

        fingerprint = str(x509Cert.digest('sha256'))

    except Exception as err:
        exception = str(err)

    certErrorLogger(domain, exitnode, error, fingerprint, exception)


def readCertOfPage(page, exitnode, certErrorLogger):
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
        # c = ssl.create_default_context()
        c = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        c.verify_mode = ssl.CERT_REQUIRED
        c.check_hostname = True
        c.load_verify_locations(cafile='mozillacerts.pem', capath=None)

        # TODO: Make sure only TorBrowser Certs are loaded (how?)

        # print('Number loaded CA certs: %d' % len(c.get_ca_certs()))
        # print(ssl.get_default_verify_paths())

        conn = httplib.HTTPSConnection(
            domain, PORT, context=c)
        conn.request(
            'GET', '/', headers=collections.OrderedDict(HTTP_HEADERS))
        # response = conn.getresponse()
    except ssl.CertificateError as err:
        handleCertError(err, domain, exitnode, certErrorLogger)

    except Exception as err:
        pass


def readCert(
        exit_fpr=None,
        certErrorLogger=logCertError,
        sitelist='special.csv'):
    """
    Read TLS certificates for all domains in sitelist.
    """

    # sitelist = 'top-1m.csv'
    # sitelist = 'special.csv'

    exit_url = util.exiturl(exit_fpr) if exit_fpr is not None else '<noTOR>'
    log.debug('Probing exit relay \"%s\".' % exit_url)

    with open(sitelist) as csvfile:
        for page in csv.DictReader(csvfile, delimiter=','):
            if exit_fpr is None:
                print('Scanning %s ...' % page['webpage'])
            readCertOfPage(page, exit_fpr, certErrorLogger)
