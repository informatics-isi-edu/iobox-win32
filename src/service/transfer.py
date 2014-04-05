import os
import hashlib
import re
import serviceconfig
import sys
import traceback

def sha256sum(fpath):
    """Return hex digest string like sha256sum utility would compute."""
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

def processFile(observer, filename, action):
    m = re.search(observer.pattern, os.path.basename(filename))
    if not m or not m.group('slideid'):
        moveFile(observer, filename, 'rejected')
    else:
        st_size = os.stat(filename).st_size
        sleep_time = st_size / 1000000000 +1
        slide_id = m.group('slideid')
        shasum = sha256sum(filename)
        fileobjs = []
        obj = {'slide_id': slide_id, 
               'filename': os.path.basename(filename),
               'sha256sum': shasum,
               'file_from': create_uri_friendly_file_path(filename),
               'file_to': '/scans/%s/%s.czi' % (slide_id, shasum)}
        fileobjs.append(obj)
        serviceconfig.logger.info('Registering file: %s' % os.path.basename(filename))
        task_id, status, lastAction = observer.client.add_subjects(fileobjs, observer.http_url, st_size, observer.bulk_ops_max, action, sleep_time)
        if task_id and status == 'SUCCEEDED':
            serviceconfig.logger.info('Transfer %s: %s' % (filename, task_id))
            observer.client.sendMail('SUCCEEDED Transfer', 'The file "%s" was successfully transfered using the Globus Task ID %s' % (filename, task_id))
            if os.path.isfile('%s%s%s' % (observer.outbox, os.sep, os.path.basename(filename))):
                os.remove('%s%s%s' % (observer.outbox, os.sep, os.path.basename(filename)))
            os.rename(filename, '%s%s%s' % (observer.outbox, os.sep, os.path.basename(filename)))
        elif lastAction != None and lastAction != action:
                moveFile(observer, filename, lastAction)

def recoverFiles(observer):
    for f in os.listdir(observer.inbox):
        filename = '%s%s%s' % (observer.inbox, os.sep, f)
        if os.path.isfile(filename):
            serviceconfig.logger.debug('Recovering %s' % filename)
            try:
                processFile(observer, filename, 'recover')
            except:
                et, ev, tb = sys.exc_info()
                serviceconfig.logger.error('got Processing exception during recovering "%s"' % str(ev))
                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                observer.client.sendMail('FAILURE %s' % f, 'Exception generated during processing the file "%s":\n%s\n%s' % (filename, str(ev), str(traceback.format_exception(et, ev, tb))))

def moveFile(observer, filename, action):
    if action == 'rejected':
        toDir = observer.rejected
    elif action == 'retry':
        toDir = observer.retry
    elif action == 'transfer':
        toDir = observer.transfer
    else:
        serviceconfig.logger.error('Unknown action to move a file "%s"' % action)
        return
    
    if os.path.isfile('%s%s%s' % (toDir, os.sep, os.path.basename(filename))):
        os.remove('%s%s%s' % (toDir, os.sep, os.path.basename(filename)))
    serviceconfig.logger.info('Rejected file: %s' % os.path.basename(filename))
    os.rename(filename, '%s%s%s' % (toDir, os.sep, os.path.basename(filename)))
    observer.client.sendMail('FAILURE %s' % os.path.basename(filename), 'The file "%s" was moved to the "%s" directory.' % (os.path.basename(filename), action))

def processRetry(observer):
    try:
        retryFiles = [ f for f in os.listdir(observer.retry) if os.path.isfile(os.path.join(observer.retry,f)) ]
        if len(retryFiles) > 0:
            try:
                observer.client.connect();
            except:
                et, ev, tb = sys.exc_info()
                serviceconfig.logger.error('got exception during reconnecting "%s"' % str(ev))
                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                observer.client.sendMail('FAILURE Reconnect', 'Exception generated during reconnecting to ERMREST:\n%s\n%s' % (str(ev), str(traceback.format_exception(et, ev, tb))))
        for f in retryFiles:
            processFile(observer, os.path.join(observer.retry,f), 'retry')
            
        transferFiles = [ f for f in os.listdir(observer.transfer) if os.path.isfile(os.path.join(observer.transfer,f)) ]
        for f in transferFiles:
            processFile(observer, os.path.join(observer.transfer,f), 'transfer')
    except:
        et, ev, tb = sys.exc_info()
        serviceconfig.logger.error('got Processing exception during retry "%s"' % str(ev))
        serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
        observer.client.sendMail('FAILURE', 'Exception generated during the retry process:\n%s\n%s' % (str(ev), str(traceback.format_exception(et, ev, tb))))
        
