#!/usr/bin/env python
# 
# Copyright 2014 University of Southern California
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
"""
Raw network client for HTTP(S) communication with ERMREST service.
"""

import os
import json
import base64
import urlparse
from httplib import HTTPConnection, HTTPSConnection, HTTPException, OK, CREATED, ACCEPTED, NO_CONTENT, CONFLICT
from globusonline.transfer import api_client
from datetime import datetime, timedelta
import sys
import traceback
import time
import shutil
from transfer import create_uri_friendly_file_path
import serviceconfig

_base_html = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
        <script type="text/javascript" src="/cirm-usc/zoomify/ZoomifyImageViewer.js"></script>
        <style type="text/css"> #myContainer { width:900px; height:550px; margin:auto; border:1px; border-style:solid; border-color:#696969;} </style>
        <script type="text/javascript"> Z.showImage("myContainer", "/cirm-usc/tiles/%(slide_id)s/%(scan_id)s", "zInitialZoom=50&zFullPageInitial=1&zLogoVisible=0&zSkinPath=/cirm-usc/zoomify/Assets/Skins/Default"); </script>
    </head>
    <body>
        <div id="myContainer"></div>
    </body>
</html>
"""

class ErmrestHTTPException(Exception):
    def __init__(self, value, status):
        super(ErmrestHTTPException, self).__init__(value)
        self.value = value
        self.status = status
        
    def __str__(self):
        message = "%s." % self.value
        return message

class ErmrestException(Exception):
    def __init__(self, value, cause=None):
        super(ErmrestException, self).__init__(value)
        self.value = value
        self.cause = cause
        
    def __str__(self):
        message = "%s." % self.value
        if self.cause:
            message += " Caused by: %s." % self.cause
        return message

class MalformedURL(ErmrestException):
    """MalformedURL indicates a malformed URL.
    """
    def __init__(self, cause=None):
        super(MalformedURL, self).__init__("URL was malformed", cause)

class UnresolvedAddress(ErmrestException):
    """UnresolvedAddress indicates a failure to resolve the network address of
    the Ermrest service.
    
    This error is raised when a low-level socket.gaierror is caught.
    """
    def __init__(self, cause=None):
        super(UnresolvedAddress, self).__init__("Could not resolve address of host", cause)

class NetworkError(ErmrestException):
    """NetworkError wraps a socket.error exception.
    
    This error is raised when a low-level socket.error is caught.
    """
    def __init__(self, cause=None):
        super(NetworkError, self).__init__("Network I/O failure", cause)

class ProtocolError(ErmrestException):
    """ProtocolError indicates a protocol-level failure.
    
    In other words, you may have tried to add a tag for which no tagdef exists.
    """
    def __init__(self, message='Network protocol failure', errorno=-1, response=None, cause=None):
        super(ProtocolError, self).__init__("Ermrest protocol failure", cause)
        self._errorno = errorno
        self._response = response
        
    def __str__(self):
        message = "%s." % self.value
        if self._errorno >= 0:
            message += " HTTP ERROR %d: %s" % (self._errorno, self._response)
        return message
    
class NotFoundError(ErmrestException):
    """Raised for HTTP NOT_FOUND (i.e., ERROR 404) responses."""
    pass


class ErmrestClient (object):
    """Network client for ERMREST.
    """
    ## Derived from the ermrest iobox service client

    def __init__(self, baseuri, username, password, endpoint_1, endpoint_2, use_goauth=False):
        self.baseuri = baseuri
        o = urlparse.urlparse(self.baseuri)
        self.scheme = o[0]
        host_port = o[1].split(":")
        self.host = host_port[0]
        self.path = o.path
        self.port = None
        if len(host_port) > 1:
            self.port = host_port[1]
        self.use_goauth = use_goauth
        self.username = username
        self.password = password
        self.endpoint_1 = endpoint_1
        self.endpoint_2 = endpoint_2
        self.header = None
        self.webconn = None

    def send_request(self, method, url, body='', headers={}):
        if self.header:
            headers.update(self.header)
        self.webconn.request(method, url, body, headers)
        resp = self.webconn.getresponse()
        if resp.status not in [OK, CREATED, ACCEPTED, NO_CONTENT]:
            raise ErmrestHTTPException("Error response (%i) received: %s" % (resp.status, resp.read()), resp.status)
        return resp

    def connect(self):
        if self.scheme == 'https':
            self.webconn = HTTPSConnection(host=self.host, port=self.port)
        elif self.scheme == 'http':
            self.webconn = HTTPConnection(host=self.host, port=self.port)
        else:
            raise ValueError('Scheme %s is not supported.' % self.scheme)

        if self.use_goauth:
            auth = base64.encodestring('%s:%s' % (self.username, self.password)).replace('\n', '')
            headers = dict(Authorization='Basic %s' % auth)
            resp = self.send_request('GET', '/service/nexus/goauth/token?grant_type=client_credentials', '', headers)
            goauth = json.loads(resp.read())
            self.access_token = goauth['access_token']
            self.header = dict(Authorization='Globus-Goauthtoken %s' % self.access_token)
        else:
            headers = {}
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            resp = self.send_request("POST", "/ermrest/authn/session", "username=%s&password=%s" % (self.username, self.password), headers)
            self.header = dict(Cookie=resp.getheader("set-cookie"))
        
    def add_subjects(self, fileobjs, http_url, st_size, bulk_ops_max, retry, sleep_time):
        """Registers a list of files in ermrest using a single request.
        
        Keyword arguments:
        
        fileobjs -- the list of register files objects 
        
        """
        
        ret = (None, None)
        chunks = len(fileobjs) / bulk_ops_max + 1
        for i in range(0, chunks):
            start = i * bulk_ops_max
            files = fileobjs[start:start+bulk_ops_max]
            body = []
            for f in files:
                slide_id = f['slide_id']
                sha256sum = f['sha256sum']
                filename = f['filename']
                file_from = f['file_from']
                file_to = '/%s' % f['file_to']
                obj = self.getScanAttributes(filename, slide_id, sha256sum, http_url,st_size)
                body.append(obj)
            url = '%s/entity/Scan' % self.path
            headers = {'Content-Type': 'application/json'}
            go_transfer = False
            try:
                self.send_request('POST', url, json.dumps(body), headers)
                go_transfer = True
            except ErmrestHTTPException, e:
                if retry and e.status == CONFLICT:
                    go_transfer = True
                else:
                    serviceconfig.logger.error('Error during POST attempt:\n%s' % str(e))
            except:
                et, ev, tb = sys.exc_info()
                serviceconfig.logger.error('got POST exception "%s"' % str(ev))
                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                return (None, None)
            
            if go_transfer == True:
                try:
                    ret = self.transfer(file_from, file_to, sleep_time, slide_id, sha256sum)
                except:
                    et, ev, tb = sys.exc_info()
                    serviceconfig.logger.error('got GO exception "%s"' % str(ev))
                    serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                    return (None, None)
        return ret
                    
        
    def getScanAttributes(self, filename, slide_id, sha256sum, http_url, st_size):
        obj = {}
        obj['ID'] = sha256sum
        obj['Slide ID'] = slide_id
        obj['GO Endpoint'] = self.endpoint_2
        obj['GO Path'] = '/scans/%s/%s.czi' % (slide_id,sha256sum)
        obj['HTTP URL'] = '%s/scans/%s/%s.czi' % (http_url,slide_id,sha256sum)
        obj['Original Filename'] = filename
        obj['Filename'] = '%s.czi' % sha256sum
        obj['File Size'] = st_size
        #obj['Thumbnail'] = '%s/thumbnails/%s/%s.jpg' % (http_url,slide_id,sha256sum)
        #obj['Zoomify'] = '%s/html/%s/%s.html' % (http_url,slide_id,sha256sum)
        return obj
    
    def close(self):
        """Closes the connection to the Ermrest service.
        
        The underlying python documentation is not very helpful but it would
        appear that the HTTP[S]Connection.close() could raise a socket.error.
        Thus, this method potentially raises a 'NetworkError'.
        """
        assert self.webconn
        try:
            self.webconn.close()
        except socket.error as e:
            raise NetworkError(e)
        finally:
            self.webconn = None

    def transfer(self, file_from, file_to, sleep_time, slide_id, sha256sum):
        label = None
        # create the client
        args = ['transfer.py']
        args.append(self.username)
        args.append('-g')
        args.append(self.access_token)
        args.append('-C')
        args.append('C:\\Python27\\Lib\\site-packages\\globusonline_transfer_api_client-0.10.16-py2.7.egg\\globusonline\\transfer\\api_client\\ca\\all-ca.pem')
        task_id = None

        try:
            api, _ = api_client.create_client_from_args(args)
            
            # check information about endpoints
            code, reason, data = api.endpoint(self.endpoint_1)
            code, reason, data = api.endpoint(self.endpoint_2)
            
            # activate endpoint
            code, reason, result = api.endpoint_autoactivate(self.endpoint_1, if_expires_in=600)
            code, reason, result = api.endpoint_autoactivate(self.endpoint_2, if_expires_in=600)
            
            # look at contents of endpoint
            code, reason, data = api.endpoint_ls(self.endpoint_1, '/')
            code, reason, data = api.endpoint_ls(self.endpoint_2, '/')
            
            # start transfer
            code, message, data = api.transfer_submission_id()
            t = api_client.Transfer(data['value'], self.endpoint_1, self.endpoint_2, deadline=datetime.utcnow() + timedelta(minutes=10), label=label)
            t.add_item(file_from, file_to)
            #self.prepareFiles(sha256sum, slide_id)
            #t.add_item(create_uri_friendly_file_path('C:\\Users\\serban\\Documents\\cirm_temp\\%s' % sha256sum), '/tiles/%s/%s' % (slide_id, sha256sum), recursive=True)
            #t.add_item(create_uri_friendly_file_path('C:\\Users\\serban\\Documents\\cirm_temp\\%s.jpeg' % sha256sum), '/thumbnails/%s/%s.jpeg' % (slide_id, sha256sum))
            #t.add_item(create_uri_friendly_file_path('C:\\Users\\serban\\Documents\\cirm_temp\\%s.html' % sha256sum), '/html/%s/%s.html' % (slide_id, sha256sum))
            
            code, reason, data = api.transfer(t)
            task_id = data['task_id']
            code, reason, data = api.task(task_id)
            while data['status'] == 'ACTIVE':
                time.sleep(sleep_time)
                code, reason, data = api.task(task_id)
            #self.cleanupFiles(sha256sum)
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('got transfer exception "%s"' % str(ev))
            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
            return (None, None)
            
        return (task_id, data['status'])

    def prepareFiles(self, sha256sum, slide_id):
        shutil.copytree('C:\\Users\\serban\\Documents\\cirm_templates\\tiles_sample', 'C:\\Users\\serban\\Documents\\cirm_temp\\%s' % sha256sum)
        shutil.copyfile('C:\\Users\\serban\\Documents\\cirm_templates\\thumbnail_sample.jpeg', 'C:\\Users\\serban\\Documents\\cirm_temp\\%s.jpeg' % sha256sum)
        self.prepareHTMLFile(sha256sum, slide_id)
        
    def cleanupFiles(self, sha256sum):
        shutil.rmtree('C:\\Users\\serban\\Documents\\cirm_temp\\%s' % sha256sum)
        os.remove('C:\\Users\\serban\\Documents\\cirm_temp\\%s.jpeg' % sha256sum)
        os.remove('C:\\Users\\serban\\Documents\\cirm_temp\\%s.html' % sha256sum)
        
    def prepareHTMLFile(self, sha256sum, slide_id):
        f = open('C:\\Users\\serban\\Documents\\cirm_temp\\%s.html' % sha256sum, 'w')
        f.write('%s\n' % _base_html % (dict(scan_id=sha256sum, slide_id=slide_id)))
        f.close()
        
        
