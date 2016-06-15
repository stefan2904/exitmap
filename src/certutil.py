#!/usr/bin/env python2

"""
Check TLS certificates for a given list of sites over all Tor exit nodes.
The purpose of this script is to find exit nodes who do MITM
by breaking the TLS connecting (SSLstrip) by using their own certificate.
"""

import httplib
import logging
import util
import ssl
import csv
import OpenSSL
import requests

# Set level of HTTP related loggers:
logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(
    level=logging.WARNING)

logging.getLogger('requests.packages.urllib3.connection').setLevel(
    level=logging.CRITICAL)

log = logging.getLogger(__name__)


PORT = httplib.HTTPS_PORT  # 443
TRUSTSTORE = 'mozillacerts.pem'
LOGSSLERRORS = False


def logCertError(domain, exitnode, error, fingerprint, exception, probeid):
    if exception is None:
        status = 'Fingerprint: %s' % fingerprint
    else:
        status = 'Exception:   %s' % exception

    print('''
        Domain:      %s
        Exitnode:    %s
        Error:       %s
        %s
        '''
          % (domain, exitnode, error, status))


def handleCertError(
        err,
        page,
        probeid,
        exitnode,
        certErrorLogger,
        logSSLerrors):
    domain = str(page['webpage'])
    exitnode = str(exitnode)
    error = str(err)
    fingerprint = None
    exception = None

    try:
        asn1Cert = ssl.get_server_certificate((domain, PORT))
        x509Cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, asn1Cert)

        fingerprint = str(x509Cert.digest('sha256'))
        if (fingerprint != page['fingerprint']):
            print('%s: fingerprint mismatch found' % (domain))
            foundLogger(page, exitnode, fingerprint)
        else:
            print('%s: fingerprint OK' % (domain))

    except Exception as err:
        exception = str(err)

    if logSSLerrors:
        certErrorLogger(
            domain,
            exitnode,
            error,
            fingerprint,
            exception,
            int(probeid))


def foundLogger(page, exitnode, fingerprint):
    fd = open('found.csv', 'a')
    message = '%s,%s,%s,%s,%s\n' % (page['id'],
                                    page['webpage'],
                                    exitnode,
                                    page['fingerprint'], fingerprint)
    fd.write(message)
    fd.close()

    print('''
        Domain:      %s
        Exitnode:    %s
        Fingerprint:       %s
        Expected fingerprint: %s
        '''
          % (page['webpage'], exitnode, fingerprint, page['fingerprint']))


def readCertOfPage(page, exitnode, certErrorLogger, logSSLerrors):
    """
    Read TLS certificate for the given page.
    Handle certificate errors accordingly.
    """

    domain = page['webpage']
    probeid = page['id']
    http_headers = {
        'Host':
        domain,
        'User-Agent':
        'Mozilla/5.0 (Windows NT 6.1; rv:38.0) Gecko/20100101 Firefox/38.0',
        'Accept':
        'text/html,application/xhtml+xml,'
        'application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language':
        'en-US,en;q=0.5',
        'Accept-Encoding':
        'gzip, deflate',
        'Content-Length':
        '0'}

    try:
        requests.get(
            'https://' + domain,
            timeout=2,
            headers=http_headers,
            verify=TRUSTSTORE).text

    except requests.exceptions.SSLError as err:
        handleCertError(
            err,
            page,
            probeid,
            exitnode,
            certErrorLogger,
            logSSLerrors)
    except requests.exceptions.Timeout as err:
        print('%s: timeout' % (domain))
    except Exception as err:
        pass


def readCert(
        exit_fpr=None,
        certErrorLogger=logCertError,
        sitelist='filtered.csv',
        logSSLerrors=LOGSSLERRORS):
    """
    Read TLS certificates for all domains in sitelist.
    """

    exit_url = util.exiturl(exit_fpr) if exit_fpr is not None else '<noTOR>'
    log.debug('Probing exit relay \"%s\".' % exit_url)

    with open(sitelist) as csvfile:
        for page in csv.DictReader(csvfile, delimiter=','):
            if exit_fpr is None:
                print('Scanning %s ...' % page['webpage'])
            readCertOfPage(page, exit_fpr, certErrorLogger, logSSLerrors)
