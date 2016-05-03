import os
import serviceconfig
import sys
import json
import urlparse
import traceback
import time
import winerror
import errno
from client import ErmrestHTTPException, ErmrestClient
from httplib import CONFLICT, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT, REQUEST_TIMEOUT

"""
Class for applying the workflow rules.
"""
class Workflow(object):
    
    def __init__(self, **kwargs):
        observer = kwargs.get("observer")
        self.rules = observer.rules
        self.clients = observer.clients
        self.success = observer.success
        self.failure = observer.failure
        self.transfer = observer.transfer
        self.retry = observer.retry
        self.inbox = observer.inbox
        self.basicDict = observer.basicDict

    """
    Retry uploading the files.
    """
    def processRetry(self):
        try:
            retryFiles = [ f for f in os.listdir(self.retry) if os.path.isfile(os.path.join(self.retry,f)) ]
            for f in retryFiles:
                self.processFile(os.path.join(self.retry,f), 'retry')
                
            transferFiles = [ f for f in os.listdir(self.transfer) if os.path.isfile(os.path.join(self.transfer,f)) ]
            for f in transferFiles:
                self.processFile(os.path.join(self.transfer,f), 'transfer')
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('got Processing exception during retry "%s"' % str(ev))
            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
            serviceconfig.sendMail('FAILURE', 'Exception generated during the retry process:\n%s\n%s' % (str(ev), ''.join(traceback.format_exception(et, ev, tb))))
        
    """
    Recover uploading the files.
    """
    def recoverFiles(self):
        for f in os.listdir(self.inbox):
            filename = '%s%s%s' % (self.inbox, os.sep, f)
            if os.path.isfile(filename):
                serviceconfig.logger.debug('Recovering %s' % filename)
                try:
                    self.processFile(filename, 'recover')
                except:
                    et, ev, tb = sys.exc_info()
                    serviceconfig.logger.error('got Processing exception during recovering "%s"' % str(ev))
                    serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                    serviceconfig.sendMail('FAILURE %s' % f, 'Exception generated during processing the file "%s":\n%s\n%s' % (filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
    
    """
    Upload a file.
    """
    def processFile(self, filename, action):
        self.findRule(filename)
        if self.rule:
            self.applyDisposition(action)
        else:
            self.moveFile(filename, 'failure')
    
    """
    Find the rule for uploading a file.
    """
    def findRule(self, filename):
        self.rule = None
        for rule in self.rules:
            pattern = rule.get('pattern', None)
            if pattern:
                groups = self.basicDict['patterngroups'](pattern, filename, '')
                if groups:
                    self.rule = rule
                    self.filename = filename
                    serviceconfig.logger.debug('rule: "%s"' % pattern)
                    break

    """
    Apply the dispositions of the rule.
    """
    def applyDisposition(self, action):
        complete = True
        ouputDict = dict()
        ouputDict.update({'basename': self.basicDict['basename'](self.filename)})
        ouputDict.update({'nbytes': self.basicDict['nbytes'](self.filename)})
        for disposition in self.rule['disposition']:
            if disposition['handler'] == 'patterngroups':
                """
                Add the pattern groups.
                """
                pattern = self.rule.get('pattern', None)
                prefix = disposition.get('prefix', '') % ouputDict
                groups = self.basicDict['patterngroups'](pattern, self.filename, prefix)
                if groups:
                    for group in groups.keys():
                        ouputDict.update({group: groups[group]})
            elif disposition['handler'] == 'sha256':
                """
                Add the checksum of the file.
                """
                prefix = disposition.get('prefix', '') % ouputDict
                sha256 = self.basicDict['sha256sum'](self.filename)
                ouputDict.update({'%ssha256' % prefix: sha256})
            elif disposition['handler'] == 'urlQuote':
                """
                Add the URL encode values.
                """
                prefix = disposition.get('prefix', '') % ouputDict
                resources = disposition['resources']
                for resource in resources.keys():
                    value = resources[resource] % ouputDict
                    quote = self.basicDict['urlQuote'](value, safe='')
                    ouputDict.update({'%s%s' % (prefix, resource): quote})
            elif disposition['handler'] == 'templates':
                """
                Add the templates.
                """
                prefix = disposition.get('prefix', '') % ouputDict
                templates = disposition['templates']
                for template in templates.keys():
                    value = templates[template] % ouputDict
                    ouputDict.update({'%s%s' % (prefix, template): value})
            elif disposition['handler'] == 'webconn':
                """
                Add Web Client connections.
                """
                connections = disposition['connections']
                prefix = disposition.get('prefix', '') % ouputDict
                for key in connections.keys():
                    webcli = self.clients.get('%s%s' % (prefix, key), None)
                    if webcli == None:
                        connection = connections[key]
                        webcli = ErmrestClient(scheme=connection.get('scheme', None), \
                                               host=connection.get("host", None), \
                                               port=connection.get("port", None), \
                                               use_goauth=connection.get("use_goauth", False), \
                                               username=connection.get("username", None), \
                                               password=connection.get("password", None), \
                                               cookie=connection.get("cookie", None))
                        webcli.connect()
                        self.clients.update({'%s%s' % (prefix, key): webcli})
                    ouputDict.update({'%s%s' % (prefix, key): webcli})
            elif disposition['handler'] == 'ermrest':
                """
                Execute an ermrest request.
                """
                method = disposition.get('method', None)
                url = disposition.get('url', None) % ouputDict
                webcli = ouputDict[disposition.get('webconn', None) % ouputDict]
                failure = disposition.get('failure', None)
                body = []
                if method == 'POST':
                    """
                    Build the POST body.
                    """
                    colmap = disposition.get('colmap', {})
                    cols = dict()
                    for col in colmap.keys():
                        try:
                            value = colmap[col] % ouputDict
                        except:
                            value = colmap[col]
                        cols.update({col: value})
                    body.append(cols)
                    serviceconfig.logger.debug("POST body: %s" % json.dumps(body))
                elif method == 'PUT':
                    """
                    Build the PUT target.
                    """
                    group_key = disposition.get('group_key', {})
                    group_cols = []
                    for col in group_key.keys():
                        group_cols.append(self.basicDict['urlQuote'](col))
                    target_columns = disposition.get('target_columns', {})
                    target_cols = []
                    for col in target_columns.keys():
                        target_cols.append(self.basicDict['urlQuote'](col))
                    url = '%s/%s;%s' % (url, ','.join(group_cols), ','.join(target_cols))
                    serviceconfig.logger.debug("PUT url: %s" % url)
                    """
                    Build the PUT body.
                    """
                    cols = dict()
                    for col in group_key.keys():
                        value = group_key[col] % ouputDict
                        cols.update({col: value})
                    for col in target_columns.keys():
                        value = target_columns[col] % ouputDict
                        cols.update({col: value})
                    body.append(cols)
                    serviceconfig.logger.debug("PUT body: %s" % json.dumps(body))
                if webcli:
                    """
                    Send the ermrest request
                    """
                    success=False
                    try:
                        headers = {'Content-Type': 'application/json'}
                        resp = webcli.send_request(method, self.basicDict['urlPath'](url), json.dumps(body), headers)
                        resp.read()
                        success = True
                        serviceconfig.sendMail('SUCCEEDED ERMREST', '%s: %s\n%s' % (method, url, body))
                    except ErmrestHTTPException, e:
                        if method == 'POST' and e.status == CONFLICT:
                            success = True
                        else:
                            if e.status in [0, REQUEST_TIMEOUT, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT]:
                                failure = 'retry'
                            serviceconfig.sendMail('FAILURE ERMREST', 'Error generated during the %s request: %s\n%s' % (method, url, str(e)))
                    except:
                        et, ev, tb = sys.exc_info()
                        serviceconfig.sendMail('FAILURE ERMREST', 'Exception generated during the %s request: %s\n%s\n%s' % (method, url, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                    if success==False and failure:
                        serviceconfig.logger.debug("failure action: %s" % json.dumps(ouputDict))
                    if success==False:
                        complete = False
                        self.moveFile(self.filename, failure)
                        break
            elif disposition['handler'] == 'hatrac':
                """
                Upload the file.
                """
                url = disposition.get('url', None) % ouputDict
                chunk_size = disposition.get('chunk_size', 100000000)
                webcli = ouputDict[disposition.get('webconn', None) % ouputDict]
                failure = disposition.get('failure', None)
                create_parents = disposition.get('create_parents', False)
                o = urlparse.urlparse(url)
                object_url = o.path
                pathes = o.path.split('/')[:-1]
                namespaces = pathes[2:]
                res = webcli.retrieveNamespace('/'.join(pathes))
                if res == None:
                    """
                    Parent namespace does not exist
                    """
                    success = False
                    if create_parents == True:
                        """
                        Create parent namespace
                        """
                        urls = pathes[0:2]
                        for namespace in namespaces:
                            urls.append(namespace)
                            serviceconfig.logger.debug("urls: %s" % urls)
                            if webcli.retrieveNamespace('/'.join(urls)) == None:
                                try:
                                    webcli.createNamespace('/'.join(urls))
                                    success = True
                                except ErmrestHTTPException, e:
                                    success = False
                                    serviceconfig.sendMail('FAILURE ERMREST', 'ErmrestHTTPException: Can not create namespace "%s"\n. Error: "%s"' % ('/'.join(urls), str(e)))
                                    break
                                except:
                                    success = False
                                    break
                        if success == False:
                            complete = False
                            self.moveFile(self.filename, failure)
                            break
                    else:
                        serviceconfig.sendMail('FAILURE ERMREST', 'Namespace "%s" does not exist.' % '/'.join(namespaces))
                        complete = False
                        self.moveFile(self.filename, failure)
                        break
                try:
                    job_id, status = webcli.uploadFile(object_url, self.filename, chunk_size)
                    serviceconfig.sendMail('SUCCEEDED TRANSFER', 'File "%s" was uploaded at "%s"' % (self.filename, object_url))
                except:
                    et, ev, tb = sys.exc_info()
                    serviceconfig.logger.error('Can not transfer file "%s" in namespace "%s". Error: "%s"' % (self.filename, object_url, str(ev)))
                    complete = False
                    self.moveFile(self.filename, failure)
                    serviceconfig.sendMail('FAILURE TRANSFER', 'Can not transfer file "%s" in namespace "%s". Error: "%s"' % (self.filename, object_url, str(ev)))
                    break
        if complete == True:
            self.moveFile(self.filename, 'success')

    """
    Check if the file is ready for processing, i.e. if copy/move into the directory has finished.
    """
    def fileIsReady(self, filename):
        try:
            time.sleep(1)
            lockFile = filename + ".lckchk"
            if(os.path.exists(lockFile)):
                os.remove(lockFile)
            os.rename(filename, lockFile)
            time.sleep(1)
            os.rename(lockFile, filename)
            return True
        except WindowsError, e:
            if e.winerror == winerror.ERROR_SHARING_VIOLATION:
                return False
            else:
                et, ev, tb = sys.exc_info()
                serviceconfig.logger.error('got WindowsError on checking if the file "%s" is ready for procesing.' % str(ev))
                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                return None
        except IOError,e:
            if e.errno == errno.EACCES:
                return False
            else:
                et, ev, tb = sys.exc_info()
                serviceconfig.logger.error('got IOError on checking if the file "%s" is ready for procesing.' % str(ev))
                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                serviceconfig.sendMail('FAILURE %s' % file, 'Exception generated during on checking if the new file "%s" is ready:\n%s\n%s' % (filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                return None
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('got Exception on checking if the file "%s" is ready for procesing.' % str(ev))
            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
            serviceconfig.sendMail('FAILURE %s' % file, 'Exception generated during on checking if the new file "%s" is ready:\n%s\n%s' % (filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
            return None

    """
    Move the file into a directory based on the process result.
    """
    def moveFile(self, filename, action):
        if action == 'success':
            subject = 'SUCCESS'
        else:
            subject = 'FAILURE'
        if action == 'failure' or action == None:
            toDir = self.failure
        elif action == 'retry':
            toDir = self.retry
        elif action == 'transfer':
            toDir = self.transfer
        elif action == 'success':
            toDir = self.success
        else:
            serviceconfig.logger.error('Unknown action to move a file "%s"' % action)
            return
        
        if os.path.isfile('%s%s%s' % (toDir, os.sep, os.path.basename(filename))):
            os.remove('%s%s%s' % (toDir, os.sep, os.path.basename(filename)))
        serviceconfig.logger.info('Moved file: "%s" to the "%s" directory.' % (os.path.basename(filename), toDir))
        os.rename(filename, '%s%s%s' % (toDir, os.sep, os.path.basename(filename)))
        serviceconfig.sendMail('%s %s' % (subject, os.path.basename(filename)), 'The file "%s" was moved to the "%s" directory.' % (os.path.basename(filename), action))
    
def create_uri_friendly_file_path(filename):
    """
    Creates a full file path with uri-friendly path separators so that it can
    be used in a file:// uri
    """
    drive, tail = os.path.splitdrive(filename)
    if drive != '':
        """ Remove the ':' character from Windows drive """
        drive = drive[:-1]
    file_path = '%s%s' % (drive, tail.replace("\\","/"))
    if file_path[0] != "/":
        file_path = "/%s" % file_path
    return file_path

    