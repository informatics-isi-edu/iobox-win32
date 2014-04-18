import os
import sys
import traceback

import win32file
import win32con

import time
from transfer import processFile, recoverFiles, processRetry, fileIsReady
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

class CirmObserver(object):
    """Represents a File watcher."""
    
    def __init__(self, **kwargs):
        self.url = kwargs.get("url")
        self.inbox = kwargs.get("inbox")
        self.outbox = kwargs.get("outbox")
        self.rejected = kwargs.get("rejected")
        self.retry = kwargs.get("retry")
        self.transfer = kwargs.get("transfer")
        self.convertor = kwargs.get("convertor")
        self.tiff = kwargs.get("tiff")
        self.pattern = kwargs.get("pattern")
        self.client = kwargs.get("client")
        self.bulk_ops_max = kwargs.get("bulk_ops_max")
        self.http_url = kwargs.get("http_url")
        processRetry(self)
        recoverFiles(self)
        self.hDir = win32file.CreateFile (
            self.inbox,
            FILE_LIST_DIRECTORY,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )
        self.timeout = kwargs.get("timeout")
        self.timer = Timer(1, self.retryFiles, kwargs={'timeout': self.timeout*60})
        self.timer.start()
        
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
                        ready = fileIsReady(self, full_filename)
                        if ready == True:
                            try:
                                processFile(self, full_filename, 'new')
                            except:
                                et, ev, tb = sys.exc_info()
                                serviceconfig.logger.error('got Processing exception "%s"' % str(ev))
                                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                                self.client.sendMail('FAILURE %s' % file, 'Exception generated during the processing of the file "%s":\n%s\n%s' % (full_filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                        elif ready == False:
                            notified.append(file)
            newFiles = [ f for f in os.listdir(self.inbox) if f not in notified and os.path.isfile(os.path.join(self.inbox,f)) ]
            for f in newFiles:
                if not self.isAlive:
                    break
                full_filename = '%s%s%s' % (self.inbox, os.sep, f)
                ready = fileIsReady(self, full_filename)
                if ready == True:
                    try:
                        processFile(self, full_filename, 'new')
                    except:
                        et, ev, tb = sys.exc_info()
                        serviceconfig.logger.error('got Processing new file exception "%s"' % str(ev))
                        serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                        self.client.sendMail('FAILURE %s' % file, 'Exception generated during the processing of the new file "%s":\n%s\n%s' % (full_filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
        
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
                    processRetry(self)
                    i = 0
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('got Retry exception "%s"' % str(ev))
            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
            self.client.sendMail('FAILURE Timer' % file, 'Exception generated during the retrying process:\n%s\n%s' % (str(ev), ''.join(traceback.format_exception(et, ev, tb))))
        serviceconfig.logger.debug('Timer has stopped.')
        
    def stop(self):
        serviceconfig.logger.debug('stopping...')
        f = open('%s\\stop_service.txt' % self.inbox, 'w')
        f.close()
        self.isAlive = False
        