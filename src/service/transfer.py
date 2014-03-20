import os
import hashlib
import re
import serviceconfig

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

def processFile(observer, filename, retry):
    m = re.search(observer.pattern, os.path.basename(filename))
    if not m or not m.group('slideid'):
        moveFile(observer, filename)
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
               'file_to': '/scans/%s/%s' % (slide_id, shasum)}
        fileobjs.append(obj)
        serviceconfig.logger.info('Registering file: %s' % os.path.basename(filename))
        task_id, status = observer.client.add_subjects(fileobjs, observer.http_url, st_size, observer.bulk_ops_max, retry, sleep_time)
        if task_id and status == 'SUCCEEDED':
            serviceconfig.logger.info('Transfer %s: %s' % (filename, task_id))
            if os.path.isfile('%s%s%s' % (observer.outbox, os.sep, os.path.basename(filename))):
                os.remove('%s%s%s' % (observer.outbox, os.sep, os.path.basename(filename)))
            os.rename(filename, '%s%s%s' % (observer.outbox, os.sep, os.path.basename(filename)))
        else:
            moveFile(observer, filename)

def recoverFiles(observer):
    for f in os.listdir(observer.inbox):
        filename = '%s%s%s' % (observer.inbox, os.sep, f)
        if os.path.isfile(filename):
            serviceconfig.logger.debug('Recovering %s' % filename)
            processFile(observer, filename, True)

def moveFile(observer, filename):
    if os.path.isfile('%s%s%s' % (observer.rejected, os.sep, os.path.basename(filename))):
        os.remove('%s%s%s' % (observer.rejected, os.sep, os.path.basename(filename)))
    serviceconfig.logger.info('Rejected file: %s' % os.path.basename(filename))
    os.rename(filename, '%s%s%s' % (observer.rejected, os.sep, os.path.basename(filename)))
