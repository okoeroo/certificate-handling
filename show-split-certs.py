#!/usr/bin/python

import re
import os
import sys
import subprocess
from subprocess import Popen, PIPE, STDOUT
import tempfile


use_shell = "/bin/bash"

class MultiCertFileSplitter(object):
    def __init__(self, inputfile='/tmp/x509up_u501'):
        try:
            f = open(inputfile, "r")
        except:
            sys.exit(1)

        data = f.read()
        if len(data) == 0:
            sys.exit(1)

        self.splitCerts(data)

    def splitCerts(self, inputdata):
        for item in re.split(r"-----BEGIN ", inputdata):
            if item.startswith("RSA"):
                continue
            if len(item) > 0:
                pem_cert = "-----BEGIN " + item

                tf = tempfile.NamedTemporaryFile()

                tf.file.write(pem_cert)
                tf.file.flush()

                tf.file.seek(0)
                p = subprocess.Popen(["openssl", "x509", "-noout", "-subject", "-issuer", "-startdate", "-enddate"], stdout=PIPE, stdin=tf.file, stderr=STDOUT)
                my_stdout = p.communicate(input=pem_cert)[0]

                if p.wait() != 0:
                    print "There were some errors"

                print my_stdout
                p.stdout.close()


############### MAIN ##############
if __name__ == "__main__":
    if len(sys.argv) == 1:
        proxyfile = "/tmp/x509up_u" + str(os.getuid())

        print "Checking : " + proxyfile
        mcfs = MultiCertFileSplitter(proxyfile)
    elif len(sys.argv) == 2:
        print "Checking file : " + sys.argv[1]
        mcfs = MultiCertFileSplitter(sys.argv[1])
    else:
        print "No input will analyse your proxy file on the default location, or the given file as first argument. No exceptions."



