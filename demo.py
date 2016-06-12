import csv
import requests

# DATA = 'filtered.csv'
DATA = 'special.csv'


# http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification

# TRUSTSTORE = '/etc/ssl/certs/' # system CAs
# TRUSTSTORE = 'mozillacerts.pem' # should be the same as with Torbrowser
TRUSTSTORE = 'letsencrypt/'  # Let's encrypt CAs (should make mine pass)

with open(DATA, 'rb') as csvfile:
    reader = csv.DictReader(csvfile, delimiter=',')
    for row in reader:
        try:
            r = requests.get(
                'https://' +
                row['webpage'],
                timeout=2,
                verify=TRUSTSTORE).text

        except requests.exceptions.SSLError as ex:
            print('%s: %s' % (row['webpage'], ex))
        except requests.exceptions.Timeout as ex:
            print('%s: timeout' % (row['webpage']))
        else:
            print('%s: no exception' % row['webpage'])
        print('')


# You can pass 'verify' the path to a CA_BUNDLE file or directory with certificates of trusted CA
# If verify is set to a path to a directory, the directory must have been processed using the c_rehash utility supplied with OpenSSL.
# (c_rehash scans directories and calculates a hash value of each ".pem" file in the specified directory list and creates symbolic links for each file, where the name of the link is the hash value.)
