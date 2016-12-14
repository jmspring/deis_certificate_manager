import requests

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
                          json = { 'domain': domain },
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