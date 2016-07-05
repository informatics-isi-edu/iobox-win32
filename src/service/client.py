#!/usr/bin/env python
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

"""
Raw network client for HTTP(S) communication with ERMREST service.
"""

import os
import json
import base64
import urlparse
from httplib import HTTPConnection, HTTPSConnection, HTTPException, OK, CREATED, ACCEPTED, NO_CONTENT, CONFLICT, NOT_FOUND, FORBIDDEN, UNAUTHORIZED, BAD_REQUEST, INTERNAL_SERVER_ERROR, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT, BadStatusLine, CannotSendRequest, REQUEST_TIMEOUT
import sys
import traceback
import serviceconfig
import hashlib
import socket
import errno

class ErmrestHTTPException(Exception):
    def __init__(self, value, status, retry=False):
        super(ErmrestHTTPException, self).__init__(value)
        self.value = value
        self.status = status
        self.retry = retry
        
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


"""
Network client for ERMREST.
"""
class ErmrestClient (object):
    ## Derived from the ermrest iobox service client

    def __init__(self, **kwargs):
        self.basicDict = kwargs.get('basicDict', None)
        self.scheme = kwargs.get('scheme', None)
        self.host = kwargs.get("host", None)
        self.port = kwargs.get("port", None)
        self.username = kwargs.get("username", None)
        self.password = kwargs.get("password", None)
        self.cookie = kwargs.get("cookie", None)
        self.header = None
        self.webconn = None

    """
    Create the HTTP(S) connection.
    """
    def connect(self):
        if self.scheme == 'https':
            self.webconn = HTTPSConnection(host=self.host, port=self.port)
        elif self.scheme == 'http':
            self.webconn = HTTPConnection(host=self.host, port=self.port)
        else:
            raise ValueError('Scheme %s is not supported.' % self.scheme)

        if self.cookie:
            self.header = {'Cookie': self.cookie}
            """
            auth = base64.encodestring('%s:%s' % (self.username, self.password)).replace('\n', '')
            headers = dict(Authorization='Basic %s' % auth)
            resp = self.send_request('GET', '/service/nexus/goauth/token?grant_type=client_credentials', '', headers, webapp='')
            goauth = json.loads(resp.read())
            self.access_token = goauth['access_token']
            self.header = dict(Authorization='Globus-Goauthtoken %s' % self.access_token)
            """
        else:
            headers = {}
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            resp = self.send_request("POST", "/ermrest/authn/session", "username=%s&password=%s" % (self.username, self.password), headers, webapp='')
            self.header = dict(Cookie=resp.getheader("set-cookie"))
            resp.read()
        
    """
    Close the HTTP(S) connection.
    """
    def close(self):
        """
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

    """
    Send a request.
    """
    def send_request(self, method, url, body='', headers={}, sendData=False, ignoreErrorCodes=[], webapp='HATRAC'):
        try:
            if self.header:
                headers.update(self.header)
            serviceconfig.logger.debug('Sending request: method="%s", url="%s://%s%s", headers="%s"' % (method, self.scheme, self.host, url, headers))
            retry = False
            try:
                if sendData == False:
                    self.webconn.request(method, url, body, headers)
                else:
                    """ 
                    For file upload send the request step by step 
                    """
                    self.webconn.putrequest(method, url)
                    for key,value in headers.iteritems():
                        self.webconn.putheader(key,value)
                    self.webconn.endheaders()
                    self.webconn.send(body)
                resp = self.webconn.getresponse()
                serviceconfig.logger.debug('Response: %d' % resp.status)
            except socket.error, e:
                retry = True
                serviceconfig.logger.debug('Socket error: %d' % (e.errno))
            except (BadStatusLine, CannotSendRequest):
                retry = True
            except:
                raise
            if retry:
                """ 
                Resend the request 
                """
                self.close()
                self.connect()
                serviceconfig.sendMail('NOTICE', '%s WARNING: The HTTPSConnection has been restarted' % webapp, 'The HTTPSConnection has been restarted on "%s://%s".\n' % (self.scheme, self.host))
                serviceconfig.logger.debug('Resending request: method="%s", url="%s://%s%s"' % (method, self.scheme, self.host, url))
                if sendData == False:
                    self.webconn.request(method, url, body, headers)
                else:
                     self.webconn.putrequest(method, url)
                     for key,value in headers.iteritems():
                         self.webconn.putheader(key,value)
                     self.webconn.endheaders()
                     self.webconn.send(body)
                resp = self.webconn.getresponse()
                serviceconfig.logger.debug('Response: %d' % resp.status)
            if resp.status in [INTERNAL_SERVER_ERROR, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT]:
                """ 
                Resend the request 
                """
                self.close()
                self.connect()
                serviceconfig.sendMail('NOTICE', '%s WARNING: The HTTPSConnection has been restarted' % webapp, 'HTTP exception: %d.\nThe HTTPSConnection has been restarted on "%s://%s".\n' % (resp.status, self.scheme, self.host))
                serviceconfig.logger.debug('Resending request: method="%s", url="%s://%s%s", headers="%s"' % (method, self.scheme, self.host, url, headers))
                if sendData == False:
                    self.webconn.request(method, url, body, headers)
                else:
                     self.webconn.putrequest(method, url)
                     for key,value in headers.iteritems():
                         self.webconn.putheader(key,value)
                     self.webconn.endheaders()
                     self.webconn.send(body)
                resp = self.webconn.getresponse()
                serviceconfig.logger.debug('Response: %d' % resp.status)
            if resp.status not in [OK, CREATED, ACCEPTED, NO_CONTENT]:
                errmsg = resp.read()
                if resp.status not in ignoreErrorCodes:
                    serviceconfig.logger.error('Error response: method="%s", url="%s://%s%s", status=%i, error: %s' % (method, self.scheme, self.host, url, resp.status, errmsg))
                else:
                    serviceconfig.logger.error('Error response: %s' % (errmsg))
                raise ErmrestHTTPException("Error response (%i) received: %s" % (resp.status, errmsg), resp.status, retry)
            return resp
        except ErmrestHTTPException:
            raise
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('got HTTP exception: method="%s", url="%s://%s%s", error="%s"' % (method, self.scheme, self.host, url, str(ev)))
            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
            serviceconfig.sendMail('ERROR', '%s FAILURE: Unexpected Exception' % webapp, 'Error generated during the HTTP request: method="%s", url="%s://%s%s", error="%s"' % (method, self.scheme, self.host, url, str(ev)))
            raise

    """
    Retrieve a namespace.
    """
    def retrieveNamespace(self, namespace_path):
        try:
            url = namespace_path
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
            resp = self.send_request('GET', url, '', headers, ignoreErrorCodes=[NOT_FOUND])
            namespaces = json.loads(resp.read())
            return namespaces
        except ErmrestHTTPException, e:
            if e.status == NOT_FOUND:
                return None
            else:
                serviceconfig.logger.error('ErmrestHTTPException: Can not retrieve namespace "%s://%s%s". Error: "%s"' % (self.scheme, self.host, namespace_path, str(e)))
                raise
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('Exception: Can not retrieve namespace "%s://%s%s". Error: "%s"' % (self.scheme, self.host, namespace_path, str(ev)))
            raise

    """
    Create a namespace.
    """
    def createNamespace(self, namespace_path):
        try:
            url = namespace_path
            headers = {'Content-Type': 'application/x-hatrac-namespace', 'Accept': 'application/json'}
            resp = self.send_request('PUT', url, headers=headers)
            res = resp.read()
            serviceconfig.logger.debug('Created namespace "%s://%s%s".' % (self.scheme, self.host, namespace_path))
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('Can not create namespace "%s://%s%s". Error: "%s"' % (self.scheme, self.host, namespace_path, str(ev)))
            raise

    """
    Upload a file.
    """
    def uploadFile(self, object_url, filePath, chunk_size):
        try:
            job_id = self.createUploadJob(object_url, filePath, chunk_size)
            self.chunksUpload(object_url, filePath, job_id, chunk_size)
            self.chunksUploadFinalization(object_url, job_id)
            return (job_id, 'SUCCEEDED')
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('Can not upload file "%s" in namespace "%s://%s%s". Error: "%s"' % (filePath, self.scheme, self.host, object_url, str(ev)))
            raise

    """
    Get the md5sum file from hatrac.
    """
    def get_md5sum(self, url):
        """
            Retrieve the md5sum of a file
        """
        ret = None
        if url != None:
            headers = {'Accept': '*'}
            try:
                resp = self.send_request('HEAD', url, headers=headers, ignoreErrorCodes=[NOT_FOUND])
                resp.read()
                ret = resp.getheader('content-md5', None)
            except:
                pass
        return ret
                
    """
    Create a job for uploading a file.
    """
    def createUploadJob(self, object_url, filePath, chunk_size):
        try:
            hash_value = self.basicDict['md5sum'](filePath, chunk_size)
            file_size = os.path.getsize(filePath)
            url = '%s;upload' % object_url
            headers = {'Content-Type': 'application/json'}
            obj = {"chunk_bytes": chunk_size,
                   "total_bytes": file_size,
                   "content_md5": hash_value,
                   "content_type": "application/octet-stream"}
            resp = self.send_request('POST', url, body=json.dumps(obj), headers=headers)
            res = resp.read()
            job_id = res.split('/')[-1][:-1]
            serviceconfig.logger.debug('Created job_id "%s" for url "%s://%s%s".' % (job_id, self.scheme, self.host, url))
            return job_id
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('Can not create job for uploading file "%s" in object "%s://%s%s". Error: "%s"' % (filePath, self.scheme, self.host, url, str(ev)))
            raise

    """
    Upload a file through chunks.
    """
    def chunksUpload(self, object_url, filePath, job_id, chunk_size):
        try:
            file_size = os.path.getsize(filePath)
            chunk_no = file_size / chunk_size
            last_chunk_size = file_size % chunk_size
            f = open(filePath, "rb")
            for index in range(chunk_no):
                position = index
                body = f.read(chunk_size)
                url = '%s;upload/%s/%d' % (object_url, job_id, position)
                headers = {'Content-Type': 'application/octet-stream', 'Content-Length': '%d' % chunk_size}
                resp = self.send_request('PUT', url, body=body, headers=headers, sendData=True)
                res = resp.read()
            if last_chunk_size > 0:
                position = chunk_no
                body = f.read(chunk_size)
                url = '%s;upload/%s/%d' % (object_url, job_id, position)
                headers = {'Content-Type': 'application/octet-stream', 'Content-Length': '%d' % last_chunk_size}
                resp = self.send_request('PUT', url, body=body, headers=headers, sendData=True)
                res = resp.read()
            f.close()
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('Can not upload chunk for file "%s" in namespace "%s://%s%s" and job_id "%s". Error: "%s"' % (filePath, self.scheme, self.host, url, job_id, str(ev)))
            try:
                f.close()
                self.cancelJob(object_url, job_id)
            except:
                pass
            raise
            

    """
    Finalize the chunks upload.
    """
    def chunksUploadFinalization(self, object_url, job_id):
        try:
            url = '%s;upload/%s' % (object_url, job_id)
            headers = {}
            resp = self.send_request('POST', url, headers=headers)
            res = resp.read()
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('Can not finalize job "%s" for object "%s://%s%s". Error: "%s"' % (job_id, self.scheme, self.host, url, str(ev)))
            raise
            
    """
    Cancel a job.
    """
    def cancelJob(self, object_url, job_id):
        try:
            url = '%s;upload/%s' % (object_url, job_id)
            headers = {}
            resp = self.send_request('DELETE', url, headers=headers)
            res = resp.read()
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('Can not cancel job "%s" for object "%s://%s%s". Error: "%s"' % (job_id, self.scheme, self.host, url, str(ev)))
            raise
            
