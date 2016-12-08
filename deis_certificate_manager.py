"""
Given a message in a queue, calculates the diff of two images.  If
the difference is large enough, issue a notification.
"""

import json
import requests
import sys

from OpenSSL import crypto, SSL

class DeisRestClient:
    username = None
    password = None
    token = None
    baseUrl = None
    proxies = None

    def __init__(self, baseUrl, username, password, proxies = None):
        self.baseUrl = baseUrl
        if self.baseUrl.endswith('/'):
            self.baseUrl = self.baseUrl[:-1]
        self.username = username
        self.password = password
        if proxies:
            self.proxies = proxies

    def login(self):
        if self.username == None or self.password == None or self.baseUrl == None:
            return False
        r = requests.post(self.baseUrl + '/v2/auth/login/',
                          json = { 'username': self.username, 'password': self.password },
                          proxies = self.proxies)
        if r.status_code != 200:
            return False
        self.token = r.json()['token']
        return True

    def list_applications(self):
        if not self.token:
            if not self.login():
                return None
        r = requests.get(self.baseUrl + '/v2/apps/',
                         headers={ 'authorization': 'token ' + self.token },
                         proxies = self.proxies)
        if r.status_code != 200:
            return False
        return r.json()

    def application_detail(self, application):
        if not self.token:
            if not self.login():
                return None
        r = requests.get(self.baseUrl + '/v2/apps/' + application + '/',
                         headers={ 'authorization': 'token ' + self.token },
                         proxies = self.proxies)
        if r.status_code != 200:
            return False
        return r.json()

    def list_certs(self):
        if not self.token:
            if not self.login():
                return None
        r = requests.get(self.baseUrl + '/v2/certs/',
                         headers={ 'authorization': 'token ' + self.token },
                         proxies = self.proxies)
        if r.status_code != 200:
            return False
        return r.json()        

    def list_domains(self, app):
        if not self.token:
            if not self.login():
                return None
        r = requests.get(self.baseUrl + '/v2/apps/' + app + '/domains/',
                         headers={ 'authorization': 'token ' + self.token },
                         proxies = self.proxies)
        if r.status_code != 200:
            return False
        return r.json()

    def add_domain(self, app, domain):
        if not self.token:
            if not self.login():
                return None
        r = requests.post(self.baseUrl + '/v2/apps/' + app + '/domains/',
                          headers={ 'authorization': 'token ' + self.token },
                          json = { 'domain': domain },
                          proxies = self.proxies)
        if r.status_code != 201:
            return False
        return True

    def add_certificate(self, name, cert, key):
        if not self.token:
            if not self.login():
                return None
        r = requests.post(self.baseUrl + '/v2/certs/',
                          headers={ 'authorization': 'token ' + self.token },
                          json = { 'name': name, 'certificate': cert, 'key': key },
                          proxies = self.proxies)
        if r.status_code != 201:
            return False
        return True

    def add_domain_to_certificate(self, cert, domain):
        if not self.token:
            if not self.login():
                return None
        r = requests.post(self.baseUrl + '/v2/certs/' + cert + '/domain/',
                          headers={ 'authorization': 'token ' + self.token },
                          json = { 'domain': fqdn },
                          proxies = self.proxies)
        if r.status_code != 201:
            return False
        return True       

    def get_certificate(self, cert):
        if not self.token:
            if not self.login():
                return None
        r = requests.get(self.baseUrl + '/v2/certs/' + cert,
                         headers={ 'authorization': 'token ' + self.token },
                         proxies = self.proxies)
        if r.status_code != 200:
            return False
        return r.json()            

def generate_serial(fqdn):
    serial = 10000
    idx = 0
    for a in fqdn:
        val = ord(a) % 10
        serial = serial + (val * pow(10, idx))
        idx = idx + 1
        if idx == 4:
            break
    return serial

def generate_certificate(fqdn):
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().CN = fqdn
    cert.set_serial_number(generate_serial(fqdn))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(2*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert), \
           crypto.dump_privatekey(crypto.FILETYPE_PEM, k)

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print 'Usage: {} <deisUrl> <username> <password> <domain>'
        sys.exit(1)

    deisUrl = sys.argv[1]
    deisUsername = sys.argv[2]
    deisPassword = sys.argv[3]
    domainName = sys.argv[4]

    client = DeisRestClient(deisUrl, deisUsername, deisPassword)

    # get apps
    apps = client.list_applications()
    fqdnList = []
    if apps['count'] > 0:
        # for each app see if <app>.<domain> exists
        for app in apps['results']:
            fqdnFound = False
            fqdn = app['id'] + '.' + domainName
            fqdnList.append(fqdn)
            domains = client.list_domains(app['id'])
            if domains['count'] > 0:
                for domain in domains['results']:
                    if domain['domain'] == fqdn:
                        fqdnFound = True
                        break
            if not fqdnFound:
                # need to add domain
                print 'Adding domain for: {}.  Domain: {}'.format(app['id'], fqdn)
                r = client.add_domain(app['id'], fqdn)

    certs = client.list_certs()
    certDomains = []
    for cert in certs['results']:
        certDomains = certDomains + cert['domains']
    
    for fqdn in fqdnList:
        if fqdn not in certDomains:
            cert, key = generate_certificate(fqdn)
            if cert and key:
                # add the certificate
                print 'Adding certificate for: {}'.format(fqdn[:fqdn.index('.')]) 
                client.add_certificate(fqdn[:fqdn.index('.')], cert, key)

                # attach the domain (fqdn) to the certificate
                print 'Adding domain to certificate: {}.  Domain: {}'.format(fqdn[:fqdn.index('.')], fqdn) 
                client.add_domain_to_certificate(fqdn[:fqdn.index('.')], fqdn)
