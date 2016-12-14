"""
deis_certificate_manager.py

This program is expected to run as a Deis Workflow process.  The program
periodically queries the configured 'Deis Controller' for applications that
have been added and require a certificate.

The general assumptions for issuing certificates are:
    - the application is routable
    - the application does not currently have a certificate for the full fqdn
    - a domain named the fqdn will be associated with the application and certificate
    - the certificate will be 'named' the application name (the first part of the fqdn)
        - for example `crusty-shoe.example.com` would have a cert named `crusty-shoe`
    - if a certificate exists for the application name, but is associated with a
      different domain, an error will be logged to the console.  this situation will
      need to be manually cleaned up.

How the program works:
    - Applications are periodically queried
    - For each unseen application:
        - Does it already have a certificate?
            - If so:
                - Is the certificate, application, and domain properly configured?
                    - If so:
                        - Continue to next application.
                    - If not:
                        - Log an error and continue to next application.
            - If not:
                - Create a Deis application for the deis_cert_letencrypt_worker process.
                - Temporarily assign a domain and the fqdn to the worker application.
                - Set the worker application configuration.
                - Deploy the worker application.
                - Make a rest call to generate the certificate.
                    - The worker will make a call to the letsencrypt.org service.
                    - The certificate, private key, and certificate chain are returned.
                - Delete the worker application (this removes the domain and fqdn association.
                  from the system / worker application).
                - Add the certificate/key to Workflow
                - Create a domain for the the application
                - Assign the domain to the newly minted certificate

If should be noted, if errors occur in the certificate retrieval process, the program 
will attempt to clean up and try later for the same application.
"""
import requests
import sys
import time
import json
import threading
from os import environ
import atexit

from flask import Flask
from flask import Response
from flask import request

from deis_rest_client import DeisRestClient

# globals
shutdownRequested = False
certhandlerThread = None
stats = {
    'applications': {
        'already_configured': [],
        'certificate_added': [],
        'problem': []
    }
}

def environment_variables():
    env = {
        'deisUrl': environ.get('DEIS_CONTROLLER_URL', None),
        'deisUsername': environ.get('DEIS_USERNAME', None),
        'deisPassword': environ.get('DEIS_PASSWORD', None),
        'domainName': environ.get('DEIS_APPLICATION_DOMAIN_NAME', None),
        'letsEncryptEmail': environ.get('LETS_ENCRYPT_CERTIFICATE_EMAIL', None),
        'letsEncryptServer': environ.get('LETS_ENCRYPT_SERVER', None),
        'workerImage': environ.get('DEIS_CERTIFICATE_WORKER_IMAGE', None),
        'proxies': environ.get('HTTP_PROXIES', None),
    }
    return env

def required_environment_vars_set(env):
    if env['deisUrl'] != None and \
            env['deisUsername'] != None and \
            env['deisPassword'] != None and \
            env['domainName'] != None and \
            env['letsEncryptEmail'] != None and \
            env['letsEncryptServer'] != None and \
            env['workerImage'] != None:
        return True
    return False

def mask_sensitive_environment_variables(env):
    for key in env.keys():
        if 'PASSWORD' in key.upper():
            env[key] = '********'
    return env

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
        print 'Error requesting certificate: {}'.format(r.status_code)
        return None
    return r.json()

def all_certificate_domains(certs):
    domains = list((certs[cert]['domains']) for cert in certs)
    return [domain for subdomains in domains for domain in subdomains]

def all_application_domains(client, apps):
    result = []
    for app in apps:
        domains = client.list_domains(app)
        if domains and domains['count'] > 0:
            r = list((domain['domain']) for domain in domains['results'])
            result.extend(r)
    return result

def is_certificate_needed(client, fqdn, certs, apps):
    app = fqdn[:fqdn.index('.')]

    # does the app already have a certificate?
    if app in certs:
        # is the app properly configured?
        cert = certs[app]

        # does the certificate contain the fqdn in it's domain?
        if cert['domains'] and len(cert['domains']) > 0:
            if fqdn in cert['domains']:
                domains = client.list_domains(app)
                if not domains:
                    raise SystemError('Unable to list domains for app {}'.format(app))
                else:
                    if domains['count'] > 0:
                        if fqdn in list((domain['domain']) for domain in domains['results']):
                            return False
                        else:
                            raise SystemError('Domain {} not associated with application {}'.format(fqdn, app))
                    else:
                        raise SystemError('No domains for application {}'.format(app))
            else:
                raise SystemError('FQDN ({}) not in certificate domains.'.format(fqdn))
        else:
            raise SystemError('Certificate with name {} contains no domains.'.format(app))

    # make sure an existing domain with the same fqdn doesn't exist
    domains = all_certificate_domains(certs)
    if domains and len(domains) > 0:
        if fqdn in domains:
            SystemError('Domain ({}) already associated with another certificate.'.format(fqdn))
    domains = all_application_domains(client, apps)
    if fqdn in domains:
        # make sure the fqdn isn't associated with the correct app
        domains = client.list_domains(app)
        if fqdn in domains:
            return True
        else:
            SystemError('Domain ({}) already associated with another application.'.format(app))
    return True

def applications(client):
    result = None
    apps = client.list_applications()
    if apps and apps['count'] > 0:
        result = dict((app['id'], app) for app in apps['results'])
    return result

def certificates(client):
    result = None
    certs = client.list_certs()
    if certs and certs['count'] > 0:
        result = dict((cert['name'], cert) for cert in certs['results'])
    return result

def get_certificate_for_application(client, fqdn, letsEncryptEmail, letsEncryptServer, workerImage, proxies = None):
    error = None
    certinfo = None
    domainName = fqdn[fqdn.index('.') + 1:]

    # create an application for the worker process
    app = client.create_application()
    if app:
        appid = app['id']

        # create the configuration for the application
        config = {
            'APPLICATION_FQDN': fqdn,
            'LETS_ENCRYPT_EMAIL': letsEncryptEmail,
            'LETS_ENCRYPT_SERVER': letsEncryptServer
        }
        if client.create_config(appid, config):
            # assign the domain to the worker app
            if client.add_domain(appid, fqdn):
                # deploy the worker application
                if client.deploy_application(appid, workerImage):
                    # the worker image can take awhile to be ready, so try
                    # waiting for awhile until it comes up
                    if wait_for_cert_worker(appid, domainName, proxies=proxies):
                        certinfo = request_certificate(appid, domainName, proxies)
                        if not certinfo:
                            error = SystemError('Unable to retrieve certificate for {}'.format(appid))
                    else:
                        error = SystemError('Timeout waiting for certificate worker task.')
                else:
                    error = SystemError('Unable to deploy certificate worker task.')
            else:
                error = SystemError('Unable to assign domain {} to worker task {}'.format(fqdn, appid))
        else:
            error = SystemError('Unable to set config for app {}'.format(appid))
        # clean up
        if not client.destroy_application(appid):
            error = SystemError('Unable to destroy worker application: {}'.format(appid))
    else:
        error = SystemError('Unable to create application for worker process.')

    if certinfo:
        return certinfo
    else:
        if error:
            return error
        else:
            return SystemError('An undefined error occurred while trying to get certificate.`')

def install_certificate_for_app(client, fqdn, cert, key):
    app = fqdn[0:fqdn.index('.')]
    error = None

    # add certificate to the application
    if client.add_certificate(app, cert, key):
        # add the domain to the application
        if client.add_domain(app, fqdn):
            # add the domain to the certificate
            if client.add_domain_to_certificate(app, fqdn):
                return True
            else:
                error = SystemError('Unable to add domain {} to certificate {}'.format(fqdn, app))
        else:
            error = SystemError('Unable to add domain {} to app {}.'.format(fqdn, app))
    else:
        error = SystemError('Unable to add certificate {}.'.format(app))
    return error

def application_already_handled(app):
    global stats

    if app in stats['applications']['already_configured'] or \
            app in stats['applications']['problem'] or \
            app in stats['applications']['certificate_added']:
        return True
    return False

def application_check_loop():
    global shutdownRequested

    env = {}
    environment_ready = False
    client = None
    last_run = 0
    while not shutdownRequested:
        if not environment_ready:
            env = environment_variables()
            if required_environment_vars_set(env):
                client = DeisRestClient(env['deisUrl'], \
                                        env['deisUsername'], \
                                        env['deisPassword'], \
                                        env['proxies'])
                client.login()
                environment_ready = True
                continue
        else:
            # check every ten seconds
            if time.time() >= 10000:
                last_run = time.time()
                apps = applications(client)
                certs = certificates(client)

                for app in apps:
                    # has the application already been handled?
                    if application_already_handled(app):
                        continue
                    fqdn = '{}.{}'.format(app, env['domainName'])

                    try:
                        needcert = is_certificate_needed(client, fqdn, certs, apps)
                        if not needcert:
                            stats['applications']['already_configured'].append(app)
                            continue
                    except SystemError as se:
                        print 'Error: {}'.format(se)
                        stats['applications']['problem'].append(app)
                        continue

                    # get the certificate for the application
                    cert = get_certificate_for_application(client, \
                                                           fqdn, \
                                                           env['letsEncryptEmail'], \
                                                           env['letsEncryptServer'], \
                                                           env['workerImage'], \
                                                           proxies=env['proxies'])
                    if type(cert) is not dict:
                        stats['applications']['problem'].append(app)
                        print 'Error: {}'.format(cert)
                        continue

                    # install the certificate
                    r = install_certificate_for_app(client, fqdn, cert['cert'], cert['key'])
                    if type(r) is not bool:
                        stats['applications']['problem'].append(app)
                        print 'Error: {}'.format(r)
                    else:
                        stats['applications']['certificate_added'].append(app)
        time.sleep(0.25)

def shutdown_server():
    global certhandlerThread
    global shutdownRequested

    shutdownRequested = True

    # shutdown flask
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

    # wait for difference thread to shut down
    if certhandlerThread:
        t = certhandlerThread
        certhandlerThread = None
        t.join()

def create_app():
    app = Flask(__name__)

    @app.route('/config')
    def config():
        masked_env = mask_sensitive_environment_variables(environment_variables())
        output = json.dumps(masked_env, indent=4) + '\n'
        return Response(output, mimetype='text/plain')

    @app.route('/shutdown')
    def shutdown():
        shutdown_server()
        return Response('ok\n', mimetype='text/plain')

    @app.route('/stats')
    def stats():
        global stats
        output = '{}\n'.format(json.dumps(stats, sort_keys=True, indent=4, separators=(',', ': ')))
        return Response(output, mimetype='text/plain')

    def interrupt():
        global certhandlerThread
        global shutdownRequested
        shutdownRequested = True
        if certhandlerThread:
            certhandlerThread.join()
            certhandlerThread = None

    def start_handler():
        global certhandlerThread
        certhandlerThread = threading.Thread(target=application_check_loop)
        certhandlerThread.start()

    start_handler()
    atexit.register(interrupt)

    return app

if __name__ == '__main__':
    app = create_app()

    # Bind to PORT if defined, otherwise default to 5000.
    port = int(environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
