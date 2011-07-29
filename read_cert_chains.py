#import crypto
import os

from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1

from OpenSSL.crypto import TYPE_RSA, TYPE_DSA, Error, PKey, PKeyType
from OpenSSL.crypto import X509, X509Type, X509Name, X509NameType
from OpenSSL.crypto import X509Req, X509ReqType
from OpenSSL.crypto import X509Extension, X509ExtensionType
from OpenSSL.crypto import load_certificate, load_privatekey
from OpenSSL.crypto import dump_certificate, load_certificate_request
from OpenSSL.crypto import dump_certificate_request, dump_privatekey
from OpenSSL.crypto import PKCS7Type, load_pkcs7_data
#from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1, FILETYPE_TEXT
#from OpenSSL.crypto import PKCS12, PKCS12Type, load_pkcs12
#from OpenSSL.crypto import CRL, Revoked, load_crl
from OpenSSL.crypto import NetscapeSPKI, NetscapeSPKIType
#from OpenSSL.crypto import sign, verify

import networkx as nx

# os.path.split

class CertificatePathFinder(object):
    def __init__(self):
        self.ca_certificates = []
        G = nx.Graph()

        self.load_ca_certificates('/etc/grid-security/certificates')


    def load_ca_certificates(self, cadir='/etc/grid-security/certificates'):
        for i in os.listdir(cadir):
            if i.endswith('.0'):
                f = open(cadir + '/' + i)
                b = f.read()

                c = load_certificate(FILETYPE_PEM, b)
                d = {}

                d['file'] = i
                d['directory'] = cadir
                d['cert'] = c
                self.ca_certificates.append(d)
        print "%d CA certificates loaded" % len(self.ca_certificates)

    def indenter(self, indent):
        s = ""
        for i in xrange(indent):
            s += "    "

        return s

    def showChild(self, ca_d, ca_list, indent):
        ca = ca_d['cert']
        print "CA depth %d : %s%s in file: %s" % (indent, self.indenter(indent), str(ca.get_subject().get_components()), ca_d['file'])
#        print "CA depth %d : %s%s in file: %s" % (indent, self.indenter(indent), str(ca.get_issuer().get_components()),  ca_d['file'])

        for d in ca_list:
            c = d['cert']
            xn_subject = c.get_subject()
            xn_issuer  = c.get_issuer()

            if c.get_issuer().hash() == ca.get_subject().hash():
                M = ca_list[:]
                M.remove(d)
                self.showChild(d, M, indent + 1)
                break


    def showCertificates(self):
        if len(self.ca_certificates) == 0:
            print "No certificates loaded"

        for d in self.ca_certificates:
            c = d['cert']
            xn_subject = c.get_subject()
            xn_issuer  = c.get_issuer()

            # Check if self-signed
            if xn_subject.hash() == xn_issuer.hash():
#                print "self signed : " + str(xn_subject.get_components())

                M = self.ca_certificates[:] # create a copy
                M.remove(d)
                self.showChild(d, M, 0)

#            print x508Name.hash()
#            print x508Name.get_components()


m = CertificatePathFinder()
m.showCertificates()