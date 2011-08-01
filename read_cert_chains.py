#!/usr/bin/python

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

#import networkx as nx
#G = nx.Graph()

# os.path.split

class CertificatePathFinder(object):
    def __init__(self, cadir, match=".pem"):
        if cadir == None and cadir != '':
            print "No CA directory given to print"
            raise

        self.ca_certificates = []
        self.use_match = match

        self.load_ca_certificates(cadir)

    def load_ca_certificates(self, cadir='/etc/grid-security/certificates'):
        for i in os.listdir(cadir):
            if i.endswith(self.use_match):
            #if i.endswith('.0'):
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
        for i in xrange(indent * 4):
            s += " "

        return s

    def printAsOpenSSLoneline(self, x509name):
        res = ''
        for rdn in x509name.get_components():
            res += '/'
            res += rdn[0]
            res += '='
            res += rdn[1]

        return res
#        return str(x509name.get_components())

    def showChild(self, ca_d, ca_list, indent):
        ca = ca_d['cert']
        if indent == 0:
            print "%s \"%s\"" % (self.indenter(indent), self.printAsOpenSSLoneline(ca.get_subject()))
        else:
            print "%s \___| -> \"%s\"" % (self.indenter(indent), self.printAsOpenSSLoneline(ca.get_subject()))
        #print "%s     |     |->    File : %s, Depth: %d, Not Before: %s, Not After %s" % (self.indenter(indent), ca_d['file'], indent, ca.get_notBefore(), ca.get_notAfter())

        print "%s     |   |-> File             : %s" % (self.indenter(indent), ca_d['file'])
        print "%s     |   |-> Depth            : %d" % (self.indenter(indent), indent)
        print "%s     |   |-> Not Before       : %s" % (self.indenter(indent), ca.get_notBefore())
        print "%s     |   |-> Not After        : %s" % (self.indenter(indent), ca.get_notAfter())
        print "%s     |   |-> Serial number    : %d" % (self.indenter(indent), ca.get_serial_number())
        if ca.has_expired():
            print "%s     |   |-> Is valid         : YES" % (self.indenter(indent))
        else:
            print "%s     |   |-> Is valid         : no" % (self.indenter(indent))

        print "%s     |   #" % (self.indenter(indent))

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


m = CertificatePathFinder('/etc/grid-security/certificates', '.pem')
m.showCertificates()

