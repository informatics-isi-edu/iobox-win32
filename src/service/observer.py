# 
# Copyright 2016 University of Southern California
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import sys
import traceback

try:
    import win32file
    import win32con
except:
    from scandir import scandir, walk
    
import os
import urllib
import re
import urlparse
import hashlib
import time
import base64
from transfer import Workflow
from datetime import datetime
import json
from client import ErmrestClient, ErmrestHTTPException

import serviceconfig
from Queue import Queue

from threading import Timer
from threading import Lock
from threading import Thread

ACTIONS = {
    1 : "Created",
    2 : "Deleted",
    3 : "Updated",
    4 : "Renamed from something",
    5 : "Renamed to something"
}

FILE_LIST_DIRECTORY = 0x0001

"""
Class to manage the observers.
"""
class ObserverManager(object):
    def __init__(self, **kwargs):
        self.timeout = kwargs.get("timeout")
        self.scan_interval = kwargs.get("scan_interval")
        self.monitored_dirs = kwargs.get("monitored_dirs")
        self.report = kwargs.get("report")
        self.connections = kwargs.get("connections")
        self.clients = dict()
        self.observers = []
        self.timer = []
        self.basicDict = dict()
        self.basicDict.update({'basename': os.path.basename})
        self.basicDict.update({'nbytes': self.nbytes})
        self.basicDict.update({'mtime': self.mtime})
        self.basicDict.update({'sha256sum': self.sha256sum})
        self.basicDict.update({'md5sum': self.md5sum})
        self.basicDict.update({'md5hex': self.md5hex})
        self.basicDict.update({'sha256base64': self.sha256base64})
        self.basicDict.update({'content_checksum': self.content_checksum})
        self.basicDict.update({'patterngroups': self.patterngroups})
        self.basicDict.update({'template_match': self.template_match})
        self.basicDict.update({'template_replace': self.template_replace})
        self.basicDict.update({'urlQuote': urllib.quote})
        self.basicDict.update({'urlPath': self.urlPath})
        
    """
    Load the observers.
    """
    def load(self):
        if self.connections == None:
            serviceconfig.logger.debug('The "connections" attribute was not specified in the configuration file.')
            serviceconfig.sendMail('ERROR', 'Configuration FAILURE: No "connections" attribute', 'The "connections" attribute was not specified in the configuration file.')
            return None
        for key in self.connections.keys():
            connection = self.connections[key]
            credentials = connection.get('credentials', None)
            if credentials == None:
                serviceconfig.logger.debug("Credentials file for reports was not specified.")
                serviceconfig.sendMail('ERROR', 'Configuration FAILURE: No credentials file', 'Credentials file was not specified.')
                return None
            try:
                if os.path.exists(credentials) and os.path.isfile(credentials):
                    f = open(credentials, 'r')
                    cfg = json.load(f)
                    for credential in cfg.keys():
                        connection.update({'%s' % credential: cfg.get(credential)})
                    webcli = ErmrestClient(scheme=connection.get('scheme', None), \
                                           host=connection.get("host", None), \
                                           port=connection.get("port", None), \
                                           username=connection.get("username", None), \
                                           password=connection.get("password", None), \
                                           cookie=connection.get("cookie", None), \
                                           basicDict=self.basicDict)
                    webcli.connect()
                    self.clients.update({'%s' % (key): webcli})
                else:
                    serviceconfig.logger.debug('Bad credentials file "%s".' % credentials)
                    serviceconfig.sendMail('ERROR', 'Configuration FAILURE: Bad credentials file', 'Bad credentials file "%s".' % credentials)
                    return None
            except:
                et, ev, tb = sys.exc_info()
                serviceconfig.logger.debug('Exception generated during reading the credential %s file: %s\n%s' % (credentials, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                serviceconfig.sendMail('ERROR', 'Configuration FAILURE: %s' % str(et), 'Exception generated during reading the credential %s file: %s\n%s' % (credentials, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                return None
            
        self.reporter = None
        if self.report != None:
            self.reporter = Reporter(observers=self, \
                                     report=self.report)
            if self.reporter.validate() == False:
                self.reporter = None
        position = 0
        for monitored_dir in self.monitored_dirs:
            self.observers.append(Observer(observers=self, \
                                           position=position, \
                                           monitored_dir=monitored_dir))
            position = position + 1
            
        for watcher in self.observers:
            if watcher.load() == None:
                return None
        
        for watcher in self.observers:
            watcher.recover()
            if serviceconfig.isWin32() == True:
                watcher.enable()
        
        return self

    """
    Start the observers.
    """
    def start(self):
        if self.reporter != None:
            timer = Timer(1, self.reporter.start, kwargs={})
            self.timer.append(timer)
            timer.start()
            
        for watcher in self.observers:
            if serviceconfig.isWin32() == True:
                timer = Timer(1, watcher.start, kwargs={})
            else:
                timer = Timer(1, watcher.startScandir, kwargs={})
            self.timer.append(timer)
            timer.start()
        if serviceconfig.isWin32() == True:     
            for timer in self.timer:
                timer.join()
        else:
            activeThreads = []
            for timer in self.timer:
                activeThreads.append(timer)
            while len(activeThreads) > 0:
                for timer in activeThreads:
                    timer.join(10)
                activeThreads = []
                for timer in self.timer:
                    if timer.is_alive():
                       activeThreads.append(timer) 
    """
    Stop the observers.
    """
    def stop(self):
        if self.reporter != None:
            self.reporter.stop()
            
        for watcher in self.observers:
            watcher.stop()

        for timer in self.timer:
            timer.join()

    """
    Get the pattern groups.
    """
    def patterngroups(self, pattern, filename, prefix, relpath_matching, fromDir):
        if relpath_matching == True:
            filePath = filename[len(fromDir)+1:].replace("\\","/")
        else:
            filePath = os.path.basename(filename)
        m = re.search(pattern, filePath)
        if m:
           ret = dict() 
           for group in m.groupdict():
                ret.update({'%s%s' % (prefix, group): m.group(group)})
           return ret
        else:
            return None
        
    """
    Get the template match.
    """
    def template_match(self, pattern, source, relpath_matching):
        if relpath_matching == True:
            source = source.replace("\\","/")
        m = re.search(pattern, source)
        return m
        
    """
    Get the template replace.
    """
    def template_replace(self, pattern, source, replacement):
        try:
            p = re.compile(pattern)
            return p.sub(replacement, source)
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.debug('Exception generated during replacing in the string "%s", the occurrences identified by the pattern "%s", by the "%s" value: %s\n%s' % (source, pattern, replacement, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
            serviceconfig.sendMail('ERROR', 'Processing FAILURE: %s' % str(et), 'Exception generated during replacing in the string "%s", the occurrences identified by the pattern "%s", by the "%s" value: %s\n%s' % (source, pattern, replacement, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
            return None
        
    """
    Get the path from the URL.
    """
    def urlPath(self, uri, uri_path):
        if uri_path != None:
            return uri_path
        else:
            o = urlparse.urlparse(uri)
            index = uri.find(o.path)
            if index >= 0:
                return uri[index:]
            else:
                return ''
        
    """
    Get the file size.
    """
    def nbytes(self, filename):
        return os.stat(filename).st_size
        
    """
    Get the file last modification time.
    """
    def mtime(self, filename):
        return datetime.utcfromtimestamp(os.path.getmtime(filename))
        
    """
    Get the hexa md5 checksum of the file.
    """
    def md5hex(self, fpath):
        h = hashlib.md5()
        try:
            f = open(fpath, 'rb')
            try:
                b = f.read(4096)
                while b:
                    h.update(b)
                    b = f.read(4096)
                return h.hexdigest()
            finally:
                f.close()
        except:
            return None

    """
    Get the checksum of the file.
    """
    def sha256sum(self, fpath):
        h = hashlib.sha256()
        try:
            f = open(fpath, 'rb')
            try:
                b = f.read(4096)
                while b:
                    h.update(b)
                    b = f.read(4096)
                return h.hexdigest()
            finally:
                f.close()
        except:
            return None

    """
    Get the base64 digest string like md5 utility would compute.
    """
    def md5sum(self, fpath, chunk_size):
        h = hashlib.md5()
        try:
            f = open(fpath, 'rb')
            try:
                b = f.read(chunk_size)
                while b:
                    h.update(b)
                    b = f.read(chunk_size)
                return base64.b64encode(h.digest())
            finally:
                f.close()
        except:
            return None

    """
    Get the base64 digest string like sha256 utility would compute.
    """
    def sha256base64(self, fpath, chunk_size):
        h = hashlib.sha256()
        try:
            f = open(fpath, 'rb')
            try:
                b = f.read(chunk_size)
                while b:
                    h.update(b)
                    b = f.read(chunk_size)
                return base64.b64encode(h.digest())
            finally:
                f.close()
        except:
            return None

    """
    Get the base64 digest strings like the sha256 and the md5 utilities would compute.
    """
    def content_checksum(self, fpath, chunk_size):
        hmd5 = hashlib.md5()
        hsha256 = hashlib.sha256()
        try:
            f = open(fpath, 'rb')
            try:
                b = f.read(chunk_size)
                while b:
                    hmd5.update(b)
                    hsha256.update(b)
                    b = f.read(chunk_size)
                return (base64.b64encode(hmd5.digest()), base64.b64encode(hsha256.digest()))
            finally:
                f.close()
        except:
            return (None, None)

"""
Class to report the daily activity.
"""
class Reporter(object):
    def __init__(self, **kwargs):
        self.report = kwargs.get("report")
        observers = kwargs.get("observers")
        self.basicDict = observers.basicDict
        self.clients = observers.clients
        self.lock = Lock()

    """
    Load the reporter configuration.
    """
    def validate(self, **kwargs):
        self.output = self.report.get('output', None)
        if not self.output or not os.path.isdir(self.output):
            serviceconfig.logger.error('Output directory for reports must be given and exist.')
            serviceconfig.sendMail('ERROR', 'Report FAILURE: No output directory', 'Output directory for reports must be given and exist.')
            return False
        self.actions = self.report.get('actions', ['success', 'failure', 'duplicate', 'retry'])
        for action in self.actions:
            if action not in ['success', 'failure', 'duplicate', 'retry']:
                serviceconfig.logger.error('Report action "%s" is invalid.' % action)
                serviceconfig.sendMail('ERROR', 'Report FAILURE: Invalid action name', 'Report action "%s" is invalid. Valid values are ["success", "failure", "duplicate", "retry"]' % action)
                return False
        self.catalog = self.report.get('catalog', 1)
        self.filename = self.report.get('prefix', 'Report')
        self.schema = self.report.get('schema', None)
        if self.schema == None:
            serviceconfig.logger.error('Schema for reports must be given.')
            serviceconfig.sendMail('ERROR', 'Report FAILURE: No schema given', 'Schema for reports must be given.')
            return False
        self.table = self.report.get('table', None)
        if self.table == None:
            serviceconfig.logger.error('Table for reports must be given.')
            serviceconfig.sendMail('ERROR', 'Report FAILURE: No table given', 'Table for reports must be given.')
            return False
        self.columns = self.report.get('colmap', None)
        if self.columns == None:
            serviceconfig.logger.error('Columns Map for the reports table must be given.')
            serviceconfig.sendMail('ERROR', 'Report FAILURE: Columns Map not given', 'Columns Map for the reports table must be given.')
            return False
        for col in ['timestamp', 'filename', 'status', 'reason', 'reported']:
            if col not in self.columns.keys():
                serviceconfig.logger.error('Report column "%s" must be provided.' % col)
                serviceconfig.sendMail('ERROR', 'Report FAILURE: Column not provided', 'Report column "%s" must be provided.' % col)
                return False
        self.webconn = self.report.get('webconn', None)
        if self.webconn == None:
            serviceconfig.logger.error('Connection for the reports must be given.')
            serviceconfig.sendMail('ERROR', 'Report FAILURE: HTTP connection not given', 'Connection for the reports must be given.')
            return False
        self.webcli = self.clients.get('%s' % (self.webconn), None)
        if self.webcli == None:
            serviceconfig.logger.debug("Web Connection for reports does not exist.")
            serviceconfig.sendMail('ERROR', 'Report FAILURE: No Web Connection', 'Web Connection for reports does not exist.')
            return False
        self.defaults = []
        url = '/ermrest/catalog/%d/schema/%s/table/%s/column' % (self.catalog, self.basicDict['urlQuote'](self.schema, safe=''), self.basicDict['urlQuote'](self.table, safe=''))
        try:
            resp = self.webcli.send_request('GET', url, headers={'Content-Type': 'application/json'}, webapp='ERMREST')
            cols = json.load(resp)
            for col in cols:
                if col['name'] not in self.columns.values():
                    self.defaults.append(col['name'])
        except ErmrestHTTPException, e:
            serviceconfig.logger.debug('Error generated during the introspection request for the report table "%s":\n%s' % (url, str(e)))
            serviceconfig.sendMail('ERROR', 'ERMREST GET FAILURE: %d' % e.status, 'Error generated during the introspection request for the report table "%s":\n%s' % (url, str(e)))
            return False
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
            serviceconfig.sendMail('ERROR', 'ERMREST GET FAILURE: %s' % str(et), 'Exception generated during the introspection request for the report table "%s": %s\n%s' % (url, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
            return False
        self.post_url = '/ermrest/catalog/%d/entity/%s:%s' % (self.catalog, self.basicDict['urlQuote'](self.schema, safe=''), self.basicDict['urlQuote'](self.table, safe=''))
        if len(self.defaults) > 0:
            defaults = []
            for col in self.defaults:
                defaults.append(self.basicDict['urlQuote'](col, safe=''))
            self.post_url = '%s?defaults=%s' % (self.post_url, ','.join(defaults))
        self.put_url = '/ermrest/catalog/%d/attributegroup/%s:%s/src:=%s;dest:=%s' % (self.catalog, \
                                                                                    self.basicDict['urlQuote'](self.schema, safe=''), \
                                                                                    self.basicDict['urlQuote'](self.table, safe=''), \
                                                                                    self.basicDict['urlQuote'](self.columns['reported'], safe=''), \
                                                                                    self.basicDict['urlQuote'](self.columns['reported'], safe=''))
        self.download_url = '/ermrest/catalog/%d/attributegroup/%s:%s/%s=f/%s,%s,%s,%s@sort(%s::desc::,%s,%s)' % (self.catalog, \
                                                                                                         self.basicDict['urlQuote'](self.schema, safe=''), \
                                                                                                         self.basicDict['urlQuote'](self.table, safe=''), \
                                                                                                         self.basicDict['urlQuote'](self.columns['reported'], safe=''), \
                                                                                                         self.basicDict['urlQuote'](self.columns['timestamp'], safe=''), \
                                                                                                         self.basicDict['urlQuote'](self.columns['filename'], safe=''), \
                                                                                                         self.basicDict['urlQuote'](self.columns['status'], safe=''), \
                                                                                                         self.basicDict['urlQuote'](self.columns['reason'], safe=''), \
                                                                                                         self.basicDict['urlQuote'](self.columns['status'], safe=''), \
                                                                                                         self.basicDict['urlQuote'](self.columns['timestamp'], safe=''), \
                                                                                                         self.basicDict['urlQuote'](self.columns['filename'], safe=''))
        self.summary_url = '/ermrest/catalog/%d/attributegroup/%s:%s/%s=f/%s;Requests:=cnt(%s)' % (self.catalog, \
                                                                                                 self.basicDict['urlQuote'](self.schema, safe=''), \
                                                                                                 self.basicDict['urlQuote'](self.table, safe=''), \
                                                                                                 self.basicDict['urlQuote'](self.columns['reported'], safe=''), \
                                                                                                 self.basicDict['urlQuote'](self.columns['status'], safe=''), \
                                                                                                 self.basicDict['urlQuote'](self.columns['status'], safe=''))
        self.isAlive = True
        return True

    """
    Report an action.
    """
    def reportAction(self, workflow, filename, action, reason=None):
        if action in self.actions:
            try:
                self.lock.acquire()
                """
                Build the POST body.
                """
                body = []
                cols = dict()
                cols.update({self.columns['timestamp']: '%s' % datetime.strftime(datetime.now(), '%Y-%m-%d %H:%M:%S.%f')})
                cols.update({self.columns['filename']: filename})
                cols.update({self.columns['status']: action})
                cols.update({self.columns['reported']: 'f'})
                cols.update({self.columns['reason']: reason})

                """
                Add the missing columns with NULL values
                """
                for col in self.defaults:
                    cols.update({col: None})
                    
                body.append(cols)
                body = workflow.json2csv(body)
                try:
                    resp = self.webcli.send_request('POST', self.post_url, body=body, headers={'Content-Type': 'text/csv'}, webapp='ERMREST')
                    resp.read()
                except ErmrestHTTPException, e:
                    serviceconfig.logger.debug('Error generated during the report POST "%s":\n%s' % (self.post_url, str(e)))
                    serviceconfig.sendMail('ERROR', 'ERMREST POST FAILURE: %d' % e.status, 'Error generated during the report POST "%s":\n%s' % (self.post_url, str(e)))
                except:
                    et, ev, tb = sys.exc_info()
                    serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                    serviceconfig.sendMail('ERROR', 'ERMREST POST FAILURE: %s' % str(et), 'Exception generated during the report POST "%s": %s\n%s' % (self.post_url, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                self.lock.release()
            except:
                et, ev, tb = sys.exc_info()
                serviceconfig.logger.error('got Reporter exception "%s"' % str(ev))
                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                serviceconfig.sendMail('ERROR', 'ERMREST Report FAILURE: %s' % str(et), 'Exception generated during the report action "%s": %s\n%s' % (self.post_url, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                self.lock.release()
                    
    """
    Start the reporter.
    """
    def start(self):
        serviceconfig.logger.debug('starting the reporter...')
        today = None
        try:
            while self.isAlive:
                now = '%s' % datetime.strftime(datetime.now(), '%Y-%m-%d')
                if today == None or now > today:
                    try:
                        self.lock.acquire()
                        report = dict()
                        """
                        GET the summary
                        """
                        success = True
                        activity = True
                        try:
                            resp = self.webcli.send_request('GET', self.summary_url, headers={'Content-Type': 'application/json'}, webapp='ERMREST')
                            rows = json.load(resp)
                            if len(rows) == 0:
                               activity = False 
                            for row in rows:
                                report.update({row[self.columns['status']]: row['Requests']})
                        except ErmrestHTTPException, e:
                            serviceconfig.logger.debug('Error generated during the report summary "%s":\n%s' % (self.summary_url, str(e)))
                            serviceconfig.sendMail('ERROR', 'ERMREST GET FAILURE: %d' % e.status, 'Error generated during the report summary "%s":\n%s' % (self.summary_url, str(e)))
                            success = False
                        except:
                            et, ev, tb = sys.exc_info()
                            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                            serviceconfig.sendMail('ERROR', 'ERMREST GET FAILURE: %s' % str(et), 'Exception generated during the report summary "%s": %s\n%s' % (self.summary_url, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                            success = False
                        if success == True and activity == True:
                            """
                            Download the report
                            """
                            try:
                                resp = self.webcli.send_request('GET', self.download_url, headers={'Accept': 'text/csv'}, webapp='ERMREST')
                                filename = '%s%s%s.%s.csv' % (self.output, os.sep, self.filename, now)
                                f = open(filename, 'w')
                                f.write(resp.read())
                                f.close()
                                report.update({'output': self.output})
                                report.update({'file': '%s.%s.csv' % (self.filename, now)})
                            except ErmrestHTTPException, e:
                                serviceconfig.logger.debug('Error generated during the report download "%s":\n%s' % (self.download_url, str(e)))
                                serviceconfig.sendMail('ERROR', 'ERMREST GET FAILURE: %d' % e.status, 'Error generated during the report download "%s":\n%s' % (self.download_url, str(e)))
                                success = False
                            except:
                                et, ev, tb = sys.exc_info()
                                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                                serviceconfig.sendMail('ERROR', 'ERMREST GET FAILURE: %s' % str(et), 'Exception generated during the report download "%s": %s\n%s' % (self.download_url, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                                success = False
                        if success == True and activity == True:
                            """
                            Update the table report
                            """
                            try:
                                body = '%s,%s\n%s,%s\n' % ('src', 'dest', 'f', 't')
                                resp = self.webcli.send_request('PUT', self.put_url, body, headers={'Content-Type': 'text/csv'}, webapp='ERMREST')
                                resp.read()
                            except ErmrestHTTPException, e:
                                serviceconfig.logger.debug('Error generated during the report update "%s":\n%s' % (self.put_url, str(e)))
                                serviceconfig.sendMail('ERROR', 'ERMREST PUT FAILURE: %d' % e.status, 'Error generated during the report update "%s":\n%s' % (self.put_url, str(e)))
                                success = False
                            except:
                                et, ev, tb = sys.exc_info()
                                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                                serviceconfig.sendMail('ERROR', 'ERMREST PUT FAILURE: %s' % str(et), 'Exception generated during the report update "%s": %s\n%s' % (self.put_url, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                                success = False
                        if success == True and activity == True:
                            report.update({'today': now})
                            serviceconfig.sendReport('Summary %s' % now, report)
                        today = now
                        self.lock.release()
                    except:
                        et, ev, tb = sys.exc_info()
                        serviceconfig.logger.error('got Reporter exception "%s"' % str(ev))
                        serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                        serviceconfig.sendMail('ERROR', 'Report FAILURE: %s' % str(et), 'Exception generated during the report process:\n%s\n%s' % (str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                        self.lock.release()
                time.sleep(10)
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('got Reporter exception "%s"' % str(ev))
            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
            serviceconfig.sendMail('ERROR', 'Report FAILURE: %s' % str(et), 'Exception generated during the report process:\n%s\n%s' % (str(ev), ''.join(traceback.format_exception(et, ev, tb))))
        serviceconfig.logger.debug('Reporter has stopped.')
    
    """
    Stop the reporter.
    """
    def stop(self):
        serviceconfig.logger.debug('stopping the reporter...')
        self.isAlive = False
        
"""
Class to watch a directory.
"""
class Observer(object):
    def __init__(self, **kwargs):
        self.position = kwargs.get("position")
        self.monitored_dir = kwargs.get("monitored_dir")
        observers = kwargs.get("observers")
        self.timeout = observers.timeout
        self.scan_interval = observers.scan_interval
        self.basicDict = observers.basicDict
        self.clients = observers.clients
        self.reporter = observers.reporter

    """
    Load the observer configuration.
    """
    def load(self, **kwargs):
        self.inbox = self.monitored_dir.get('inbox', None)
        if not self.inbox or not os.path.isdir(self.inbox):
            serviceconfig.logger.error('monitored_dirs(%d): Inbox directory must be given and exist.' % self.position)
            return None
    
        self.success = self.monitored_dir.get('success', None)
        if not self.success or not os.path.isdir(self.success):
            serviceconfig.logger.error('monitored_dirs(%d): Success directory must be given and exist.' % self.position)
            return None
    
        self.failure = self.monitored_dir.get('failure', None)
        if not self.failure or not os.path.isdir(self.failure):
            serviceconfig.logger.error('monitored_dirs(%d): Failure directory must be given and exist.' % self.position)
            return None
    
        self.retry = self.monitored_dir.get('retry', None)
        if not self.retry or not os.path.isdir(self.retry):
            serviceconfig.logger.error('monitored_dirs(%d): Retry directory must be given and exist.' % self.position)
            return None
    
        self.transfer = self.monitored_dir.get('transfer', None)
        if not self.transfer or not os.path.isdir(self.transfer):
            serviceconfig.logger.error('monitored_dirs(%d): Transfer directory must be given and exist.' % self.position)
            return None
        self.rules = self.monitored_dir.get('rules', None)
        serviceconfig.logger.debug('Monitored directory "%s" initialized' % self.inbox)
        self.workflow = Workflow(observer=self)
        self.isAlive = True
        
        return self

    """
    Report an action.
    """
    def reportAction(self, filename, action, reason=None):
        if self.reporter != None:
            self.reporter.reportAction(self.workflow, filename, action, reason)
        
    """
    Recover uploading the files.
    """
    def recover(self):
        self.workflow.processRetry()
        self.workflow.recoverFiles()
        
    """
    Enable the watcher.
    """
    def enable(self):
        self.hDir = win32file.CreateFile (
            self.inbox,
            FILE_LIST_DIRECTORY,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )
        self.timer = Timer(1, self.retryFiles, kwargs={'timeout': self.timeout*60})
        self.timer.start()
        
    """
    Start the Linux watcher.
    """
    def getNewFiles(self, path):
        files = []
        for entry in scandir(path):
            if entry.is_file():
                files.append('%s/%s' % (path, entry.name))
            else:
                files.extend(self.getNewFiles('%s/%s' % (path, entry.name)))
                
        return files
        
    """
    Poll for new files.
    """
    def scanFiles(self, path):
        files = []
        for entry in os.listdir(path):
            if os.path.isfile('%s%s%s' % (path, os.sep, entry)) and not entry.endswith('.lckchk'):
                files.append('%s%s%s' % (path, os.sep, entry))
            else:
                files.extend(self.scanFiles('%s%s%s' % (path, os.sep, entry)))
        return files
    
    """
    Start the Linux watcher.
    """
    def startScandir(self):
        """
        While the service is active
        """
        while self.isAlive:
            files = self.getNewFiles(self.inbox)
            while len(files) > 0:
                for full_filename in files:
                    try:
                        self.workflow.processFile(full_filename, 'new')
                    except:
                        et, ev, tb = sys.exc_info()
                        serviceconfig.logger.error('got exception during the processing of the new file "%s"\n"%s"' % (full_filename, str(ev)))
                        serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                        serviceconfig.sendMail('ERROR', 'File Processing FAILURE: %s' % str(et), 'Exception generated during the processing of the new file "%s":\n%s\n%s' % (full_filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                        self.reportAction(full_filename, 'failure', str(et))
                files = self.getNewFiles(self.inbox)
            if self.timeout > 0:
                count = (self.timeout*60) / 10
                i = 0
                try:
                    while self.isAlive:
                        time.sleep(10)
                        i = i+1
                        if i >= count:
                            break
                except:
                    et, ev, tb = sys.exc_info()
                    serviceconfig.logger.error('got Sleep exception "%s"' % str(ev))
                    serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                    serviceconfig.sendMail('ERROR', 'Sleep Processing FAILURE: %s' % str(et), 'Exception generated during the sleep process:\n%s\n%s' % (str(ev), ''.join(traceback.format_exception(et, ev, tb))))
            else:
                self.isAlive = False
                serviceconfig.logger.info('No more files to process. Exiting...')
                
    """
    Wait for file events
    """
    def worker(self):
        while self.isAlive:
            try:
                self.queue.get(True, self.scan_interval*60)
                self.queue.task_done()
            except:
                serviceconfig.logger.debug('*** "%s": Worker thread wakes up after %d seconds time out.' % (self.inbox, self.scan_interval*60))
            
            """
            Empty the queue
            """
            while not self.queue.empty():
               self.queue.get() 
               self.queue.task_done()
               
            """
            Poll the root directory until no new files are available
            """
            files = self.scanFiles(self.inbox)
            while self.isAlive and len(files) > 0:
                if os.path.join(self.inbox, 'stop_service.txt') in files:
                    """
                    Stop service was issued
                    """
                    self.isAlive = False
                    os.remove(os.path.join(self.inbox, 'stop_service.txt'))
                    """
                    Removing a file will create an event that needs to be consumed.
                    """
                    continue
                    
                for full_filename in files:
                    if full_filename == os.path.join(self.inbox, 'ReadDirectoryChangesW.txt'):
                        os.remove(full_filename)
                        continue
                    ready = self.workflow.fileIsReady(full_filename) 
                    if ready == True:
                        try:
                            self.workflow.processFile(full_filename, 'new')
                        except:
                            et, ev, tb = sys.exc_info()
                            serviceconfig.logger.error('got Processing exception "%s"' % str(ev))
                            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                            serviceconfig.sendMail('ERROR', 'File Processing FAILURE: %s' % str(et), 'Exception generated during the processing of the file "%s":\n%s\n%s' % (full_filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                files = self.scanFiles(self.inbox)
        """
        Empty the queue before exiting the thread. Most likely it might have at least the event for removing the stop_service.txt file.
        """
        try:
            self.queue.get(True, 1)
            self.queue.task_done()
            while not self.queue.empty():
               self.queue.get() 
               self.queue.task_done()
        except:
            pass
        
    """
    Trigger a change event for files that were dropped during the recovering process.
    """
    def triggerChangeEvent(self):
        serviceconfig.logger.debug('*** "%s": Triggerring a change event...' % self.inbox)
        if serviceconfig.isWin32() == True:
            f = open('%s\\ReadDirectoryChangesW.txt' % self.inbox, 'w')
            f.close()
    """
    Start the win32 watcher.
    """
    def start(self):
        """
        If the service was stopped during the recover process,
        then delete the stop_service.txt file and exit
        """
        if self.isAlive == False:
            try:
                time.sleep(1)
                os.remove(os.path.join(self.inbox, 'stop_service.txt'))
            except:
                pass
            try:
                time.sleep(1)
                os.remove(os.path.join(self.inbox, 'ReadDirectoryChangesW.txt'))
            except:
                pass
            return
                
        serviceconfig.logger.debug('*** "%s": Starting the worker thread' % self.inbox)
        self.queue = Queue()
        t = Thread(target=self.worker)
        t.start()
        
        """
        If files were dropped during the recovering process,
        we need to handle those files
        """
        timer = Timer(1, self.triggerChangeEvent, kwargs={})
        timer.start()
        
        while self.isAlive:
            self.queue.put(win32file.ReadDirectoryChangesW (
                self.hDir,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY,
                None,
                None
            ))
        self.queue.join()
        timer.join()
        
        """
        Delete the stop_service.txt file generated by stopping the service
        """
        try:
            os.remove(os.path.join(self.inbox, 'stop_service.txt'))
        except:
            pass
        
    """
    Retry uploading the files from the retry directory.
    """
    def retryFiles(self, timeout):
        serviceconfig.logger.debug('*** "%s": Starting the Timer...' % self.inbox)
        # sleep maximum 10 seconds such that the Timer can be stopped
        count = timeout / 10
        i = 0
        try:
            while self.isAlive:
                time.sleep(10)
                i = i+1
                if i >= count:
                    self.workflow.processRetry()
                    i = 0
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('got Retry exception "%s"' % str(ev))
            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
            serviceconfig.sendMail('ERROR', 'Retry Processing FAILURE: %s' % str(et), 'Exception generated during the retrying process:\n%s\n%s' % (str(ev), ''.join(traceback.format_exception(et, ev, tb))))
        serviceconfig.logger.debug('*** "%s": Timer has stopped.' % self.inbox)
        
    """
    Stop the watcher.
    """
    def stop(self):
        serviceconfig.logger.debug('*** %s": Stopping...' % self.inbox)
        self.isAlive = False
        self.workflow.isAlive = False
        if serviceconfig.isWin32() == True:
            f = open('%s\\stop_service.txt' % self.inbox, 'w')
            f.close()
