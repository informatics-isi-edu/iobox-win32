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

import serviceconfig

from threading import Timer

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
        
        return self

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
        self.isAlive = True
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
                                serviceconfig.sendMail('ERROR', 'FAILURE %s' % file, 'Exception generated during the processing of the file "%s":\n%s\n%s' % (full_filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
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
                        serviceconfig.sendMail('ERROR', 'FAILURE %s' % file, 'Exception generated during the processing of the new file "%s":\n%s\n%s' % (full_filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
        
    """
    Retry uploading the files from the retry directory.
    """
    def retryFiles(self, timeout):
        serviceconfig.logger.debug('starting the Timer...')
        # sleep maximum 10 seconds such that the Timer can be stopped
        count = timeout / 10
        i = 0
        self.isAlive = True
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
            serviceconfig.sendMail('ERROR', 'FAILURE Timer' % file, 'Exception generated during the retrying process:\n%s\n%s' % (str(ev), ''.join(traceback.format_exception(et, ev, tb))))
        serviceconfig.logger.debug('Timer has stopped.')
        
    """
    Stop the watcher.
    """
    def stop(self):
        serviceconfig.logger.debug('stopping...')
        f = open('%s\\stop_service.txt' % self.inbox, 'w')
        f.close()
        self.isAlive = False
        