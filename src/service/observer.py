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

import win32file
import win32con

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

from threading import Timer
from threading import Lock

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
        self.monitored_dirs = kwargs.get("monitored_dirs")
        self.report = kwargs.get("report")
        self.clients = dict()
        self.observers = []
        self.timer = []
        self.basicDict = dict()
        self.basicDict.update({'basename': os.path.basename})
        self.basicDict.update({'nbytes': self.nbytes})
        self.basicDict.update({'mtime': self.mtime})
        self.basicDict.update({'sha256sum': self.sha256sum})
        self.basicDict.update({'md5sum': self.md5sum})
        self.basicDict.update({'patterngroups': self.patterngroups})
        self.basicDict.update({'urlQuote': urllib.quote})
        self.basicDict.update({'urlPath': self.urlPath})
        
    """
    Load the observers.
    """
    def load(self):
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
            timer = Timer(1, watcher.start, kwargs={})
            self.timer.append(timer)
            timer.start()
            
        for timer in self.timer:
            timer.join()

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
    def patterngroups(self, pattern, filename, prefix):
        m = re.search(pattern, os.path.basename(filename))
        if m:
           ret = dict() 
           for group in m.groupdict():
                ret.update({'%s%s' % (prefix, group): m.group(group)})
           return ret
        else:
            return None
        
    """
    Get the path from the URL.
    """
    def urlPath(self, uri):
        o = urlparse.urlparse(uri)
        index = uri.find(o.path)
        if index > 0:
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
        self.connection = self.report.get('connection', None)
        if self.connection == None:
            serviceconfig.logger.error('Connection for the reports must be given.')
            serviceconfig.sendMail('ERROR', 'Report FAILURE: HTTP connection not given', 'Connection for the reports must be given.')
            return False
        key = self.connection.keys()[0]
        webcli = self.clients.get('%s' % (key), None)
        if webcli == None:
            connection = self.connection[key]
            credentials = connection.get('credentials', None)
            if credentials == None:
                serviceconfig.logger.debug("Credentials file for reports was not specified.")
                serviceconfig.sendMail('ERROR', 'Report FAILURE: No credentials file', 'Credentials file was not specified.')
                return False
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
                    serviceconfig.sendMail('ERROR', 'Report FAILURE: Bad credentials file', 'Bad credentials file "%s".' % credentials)
                    return False
            except:
                et, ev, tb = sys.exc_info()
                serviceconfig.logger.debug('Exception generated during reading the Report credential %s file: %s\n%s' % (credentials, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                serviceconfig.sendMail('ERROR', 'Report FAILURE: %s' % str(et), 'Exception generated during reading the credential %s file: %s\n%s' % (credentials, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                return False
        self.webcli = webcli
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
    Start the watcher.
    """
    def start(self):
        """
        If the service was stopped during the recover process,
        then delete the stop_service.txt file and exit
        """
        if self.isAlive==False:
            try:
                time.sleep(1)
                os.remove(os.path.join(self.inbox, 'stop_service.txt'))
            except:
                pass
            return
                
        serviceconfig.logger.debug('starting...')
        while self.isAlive:
            #
            # ReadDirectoryChangesW takes a previously-created
            # handle to a directory, a buffer size for results,
            # a flag to indicate whether to watch subtrees and
            # a filter of what changes to notify.
            #
            results = win32file.ReadDirectoryChangesW (
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
            )
            notified = []
            for action, file in results:
                if file == 'stop_service.txt':
                    time.sleep(1)
                    self.isAlive = False
                    os.remove(os.path.join(self.inbox, file))
                if self.isAlive:
                    full_filename = os.path.join(self.inbox, file)
                    action = ACTIONS.get (action, "Unknown")
                    if action == 'Created' or action == 'Updated':
                        ready = self.workflow.fileIsReady(full_filename)
                        if ready == True:
                            try:
                                self.workflow.processFile(full_filename, 'new')
                            except:
                                et, ev, tb = sys.exc_info()
                                serviceconfig.logger.error('got Processing exception "%s"' % str(ev))
                                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                                serviceconfig.sendMail('ERROR', 'File Processing FAILURE: %s' % str(et), 'Exception generated during the processing of the file "%s":\n%s\n%s' % (full_filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                        elif ready == False:
                            notified.append(file)
            newFiles = [ f for f in os.listdir(self.inbox) if f not in notified and os.path.isfile(os.path.join(self.inbox,f)) ]
            for f in newFiles:
                if not self.isAlive:
                    break
                full_filename = '%s%s%s' % (self.inbox, os.sep, f)
                ready = self.workflow.fileIsReady(full_filename)
                if ready == True:
                    try:
                        self.workflow.processFile(full_filename, 'new')
                    except:
                        et, ev, tb = sys.exc_info()
                        serviceconfig.logger.error('got Processing new file exception "%s"' % str(ev))
                        serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                        serviceconfig.sendMail('ERROR', 'File Processing FAILURE: %s' % str(et), 'Exception generated during the processing of the new file "%s":\n%s\n%s' % (full_filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                        self.reportAction(full_filename, 'failure', str(et))
        
    """
    Retry uploading the files from the retry directory.
    """
    def retryFiles(self, timeout):
        serviceconfig.logger.debug('starting the Timer...')
        # sleep maximum 10 seconds such that the Timer can be stopped
        count = timeout / 10
        i = 0
        try:
            while self.isAlive:
                time.sleep(10)
                i+=1
                if i >= count:
                    self.workflow.processRetry()
                    i = 0
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('got Retry exception "%s"' % str(ev))
            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
            serviceconfig.sendMail('ERROR', 'Retry Processing FAILURE: %s' % str(et), 'Exception generated during the retrying process:\n%s\n%s' % (str(ev), ''.join(traceback.format_exception(et, ev, tb))))
        serviceconfig.logger.debug('Timer has stopped.')
        
    """
    Stop the watcher.
    """
    def stop(self):
        serviceconfig.logger.debug('stopping...')
        f = open('%s\\stop_service.txt' % self.inbox, 'w')
        f.close()
        self.isAlive = False
        self.workflow.isAlive = False
