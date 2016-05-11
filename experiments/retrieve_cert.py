#!/usr/bin/env python

import sys
import urllib2


def main(url):
    response = urllib2.urlopen(url)
    html = response.read()
    print(html)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        print('usage: ./%s <url>' % sys.argv[0])
