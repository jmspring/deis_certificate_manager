import json
import requests
import sys
import time

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

    def create_application(self):
        if not self.token:
            if not self.login():
                return None
        r = requests.post(self.baseUrl + '/v2/apps/',
                          headers={ 'authorization': 'token ' + self.token },
                          proxies = self.proxies)
        if r.status_code != 201:
            return None
        return r.json()

    def destroy_application(self, app):
        if not self.token:
            if not self.login():
                return None
        r = requests.delete(self.baseUrl + '/v2/apps/' + app + '/',
                            headers={ 'authorization': 'token ' + self.token },
                            proxies = self.proxies)
        if r.status_code != 204:
            return False
        return True

    def deploy_application(self, app, image):
        if not self.token:
            if not self.login():
                return None
        r = requests.post(self.baseUrl + '/v2/apps/' + app + '/builds/',
                          headers={ 'authorization': 'token ' + self.token },
                          json={ 'image': image },
                          proxies = self.proxies)
        if r.status_code != 201:
            return None
        return r.json()

    def create_config(self, app, config):
        if not self.token:
            if not self.login():
                return None
        r = requests.post(self.baseUrl + '/v2/apps/' + app + '/config/',
                          headers={ 'authorization': 'token ' + self.token },
                          json={ 'values': config },
                          proxies = self.proxies)
        if r.status_code != 201:
            return None
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
    
    def remove_domain(self, app, domain):
        if not self.token:
            if not self.login():
                return None
        r = requests.delete(self.baseUrl + '/v2/apps/' + app + '/domain/' + domain,
                            headers={ 'authorization': 'token ' + self.token },
                            proxies = self.proxies)
        if r.status_code != 204:
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

def wait_for_cert_worker(worker, domain, timeout=30, proxies=None):
    ready = False
    start = time.time()
    while not ready:
        r = requests.get('http://' + worker + '.' + domain + '/', proxies=proxies)
        if r.status_code == 200:
            ready = True
        elif time.time() - start > timeout:
            break
        else:
            time.sleep(1)
    return ready

def request_certificate(worker, domain, proxies=None):
    r = requests.get('http://' + worker + '.' + domain + '/generate_cert', proxies=proxies)
    if r.status_code != 201:
        return None
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
    if len(sys.argv) != 8:
        print 'Usage: {} <deisUrl> <username> <password> <domain> <letsencrypt email> <letsencrypt server> <worker image>'
        sys.exit(1)

    deisUrl = sys.argv[1]
    deisUsername = sys.argv[2]
    deisPassword = sys.argv[3]
    domainName = sys.argv[4]
    letsEncryptEmail = sys.argv[5]
    letsEncryptServer = sys.argv[6]
    workerImage = sys.argv[7]
    proxies = None
    
    client = DeisRestClient(deisUrl, deisUsername, deisPassword, proxies)
    r = client.login()
    if not r:
        print 'error logging in.'
        sys.exit(1)

    # get apps
    apps = client.list_applications()
    fqdnList = []
    existingFqdns = []
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
                        existingFqdns.append(fqdn)
                        fqdnFound = True
                        break

    certs = client.list_certs()
    certDomains = []
    for cert in certs['results']:
        certDomains = certDomains + cert['domains']

    for fqdn in fqdnList:
        if fqdn not in certDomains :
            # create the worker app
            r = client.create_application()
            if not r:
                print 'errpr creating app.'
                sys.exit(1)
            appid = r['id']

            # create the worker app config
            config = {
                'APPLICATION_FQDN': fqdn,
                'LETS_ENCRYPT_EMAIL': letsEncryptEmail,
                'LETS_ENCRYPT_SERVER': letsEncryptServer
            }
            if not client.create_config(appid, config):
                print 'error creating config.'
                sys.exit(1)

            # assign domain to worker app
            r = client.add_domain(appid, fqdn)
            if not r:
                print 'error adding domain: {}'.format(fqdn)
                sys.exit(1)

            # deploy app
            r = client.deploy_application(appid, workerImage)
            if not r:
                print 'error deploying worker image.'
                sys.exit(1)
   
            # wait for service to be up
            r = wait_for_cert_worker(appid, domainName, proxies)
            if not r:
                print 'cert worker did not spin up'
                sys.exit(1)

            # make request to get cert and key
            certinfo = request_certificate(appid, domainName, proxies)
            if not certinfo:
                print 'error retrieving certificate.'
                sys.exit(1)
   
            # destroy app
            r = client.destroy_application(appid)
            if not r:
                print 'error destroying worker application.'
                sys.exit(1)

            # install cert and key
            app = fqdn[0:fqdn.index('.')]
            r = client.add_certificate(app, certinfo['cert'], certinfo['key'])
            if not r:
                print 'error installing certificate and key.'
                sys.exit(1)

            # assign domain to actual app
            r = client.add_domain(app, fqdn)
            if not r:
                print 'error adding domain to app.'
                sys.exit(1)

            # add domain to certificate
            r = client.add_domain_to_certificate(app, fqdn)
            if not r:
                print 'unable to add domain to certificate.'
                sys.exit(1)
