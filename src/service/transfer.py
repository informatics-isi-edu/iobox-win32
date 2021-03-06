import os
import serviceconfig
import sys
import json
import urlparse
import traceback
import time

try:
    import winerror
except:
    pass

import errno
import re
from client import ErmrestHTTPException, ErmrestClient
from httplib import CONFLICT, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT, REQUEST_TIMEOUT
from datetime import datetime

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
        self.reporter = observer.reporter
        self.system_colnames = observer.system_colnames
        self.isAlive = True

    """
    Report an action.
    """
    def reportAction(self, filename, action, reason=None):
        if self.reporter != None:
            self.reporter.reportAction(self, filename, action, reason)
        
    """
    Get recursively the files of a directory.
    """
    def getFiles(self, parent):
        ret = []
        if parent != None:
            for f in os.listdir(parent):
                filename = '%s%s%s' % (parent, os.sep, f)
                if os.path.isfile(filename):
                    ret.append(filename)
                else:
                    ret.extend(self.getFiles(filename))
        return ret
    
    """
    Retry uploading the files.
    """
    def processRetry(self):
        try:
            retryFiles = self.getFiles(self.retry)
            for filename in retryFiles:
                if self.isAlive==False:
                    break
                serviceconfig.logger.debug('Retrying %s' % filename)
                self.processFile(filename, 'retry')
                
            transferFiles = self.getFiles(self.transfer)
            for filename in transferFiles:
                if self.isAlive==False:
                    break
                serviceconfig.logger.debug('Retrying transfer %s' % filename)
                self.processFile(filename, 'transfer')
        except:
            et, ev, tb = sys.exc_info()
            serviceconfig.logger.error('got Processing exception during retry "%s"' % str(ev))
            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
            serviceconfig.sendMail('ERROR', 'Retry Processing FAILURE: %s' % str(et), 'Exception generated during the retry process:\n%s\n%s' % (str(ev), ''.join(traceback.format_exception(et, ev, tb))))
            self.reportAction(filename, 'failure', str(et))
        
    """
    Recover uploading the files.
    """
    def recoverFiles(self):
        inboxFiles = self.getFiles(self.inbox)
        for filename in inboxFiles:
            if self.isAlive==False:
                break
            serviceconfig.logger.debug('Recovering %s' % filename)
            try:
                self.processFile(filename, 'recover')
            except:
                et, ev, tb = sys.exc_info()
                serviceconfig.logger.error('got Processing exception during recovering "%s"' % str(ev))
                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                serviceconfig.sendMail('ERROR', 'Recover Processing FAILURE: %s' % str(et), 'Exception generated during processing the file "%s":\n%s\n%s' % (filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                self.reportAction(filename, 'failure', str(et))
    
    """
    Upload a file.
    """
    def processFile(self, filename, action):
        if action in ['new', 'recover'] :
            fromDir = self.inbox
        elif action == 'retry':
            fromDir = self.retry
        elif action == 'transfer':
            fromDir = self.transfer
        else:
            fromDir = None
        rule = self.findRule(filename, fromDir)
        if rule:
            try:
                self.applyDisposition(fromDir, rule, dict(), False, ['.*'], [])
            except:
                et, ev, tb = sys.exc_info()
                serviceconfig.logger.error('got Processing exception during applyDisposition "%s"' % str(ev))
                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                self.moveFile(filename, 'failure', fromDir, rule.get('dir_cleanup_patterns', ['.*']))
        else:
            serviceconfig.logger.error('No rule found for file %s' % filename)
            serviceconfig.sendMail('ERROR', 'File Processing FAILURE: No rule found', 'No rule found for file %s' % filename)
            self.reportAction(filename, 'failure', 'No rule found')
            self.moveFile(filename, 'failure', fromDir, [])
    
    """
    Find the rule for uploading a file.
    """
    def findRule(self, filename, fromDir):
        ret = None
        for rule in self.rules:
            relpath_matching = rule.get('relpath_matching', False)
            pattern = rule.get('pattern', None)
            if pattern:
                groups = self.basicDict['patterngroups'](pattern, filename, '', relpath_matching, fromDir)
                if groups != None:
                    ret = rule
                    self.filename = filename
                    serviceconfig.logger.debug('rule: "%s" applied to file: "%s"' % (pattern, filename))
                    break
        return ret

    """
    Find the inner rule for uploading a file.
    """
    def findInnerRule(self, rules, fromDir):
        ret = None
        for rule in rules:
            relpath_matching = rule.get('relpath_matching', False)
            pattern = rule.get('pattern', None)
            if pattern:
                groups = self.basicDict['patterngroups'](pattern, self.filename, '', relpath_matching, fromDir)
                if groups != None:
                    ret = rule
                    serviceconfig.logger.debug('inner rule: "%s" applied to file: "%s"' % (pattern, self.filename))
                    break
        return ret

    """
    Update the output dictionary with the values returned by a GET, POST or PUT request.
    The update will occur only if a single row is returned.
    """
    def updateDictionary(self, rows, outputDict):
        if len(rows) == 1:
            row = rows[0]
            for col in row.keys():
                outputDict.update({col: row[col]})
                outputDict.update({'encode.%s' % col: self.basicDict['urlQuote'](col, safe='')})
                value = row[col]
                if value != None:
                    try:
                        value = self.basicDict['urlQuote'](value, safe='')
                    except:
                        pass
                outputDict.update({'encode.value.%s' % col: value})

    """
    Expand the value using the dictionary-based string formatting.
    """
    def expandValue(self, value, outputDict):
        try:
            ret = value % outputDict
        except:
            ret = value
        return ret

    """
    Apply the dispositions of the rule.
    """
    def applyDisposition(self, fromDir, rule, outputDict, isInnerRule, dir_cleanup_patterns, results):
        if len(outputDict) == 0:
            outputDict.update({'basename': self.basicDict['basename'](self.filename)})
            outputDict.update({'nbytes': self.basicDict['nbytes'](self.filename)})
        complete = True
        dir_cleanup_patterns = rule.get('dir_cleanup_patterns', dir_cleanup_patterns)
        for disposition in rule['disposition']:
            if disposition['handler'] == 'patterngroups':
                """
                Add the pattern groups.
                """
                relpath_matching = rule.get('relpath_matching', False)
                pattern = rule.get('pattern', None)
                prefix = disposition.get('prefix', '') % outputDict
                groups = self.basicDict['patterngroups'](pattern, self.filename, prefix, relpath_matching, fromDir)
                if groups:
                    for group in groups.keys():
                        outputDict.update({group: groups[group]})
            elif disposition['handler'] == 'template_replace':
                """
                Replace in a string the occurrences identified by a pattern by a replacement value.
                Required fields:
                    - source: the string to be replaced
                    - pattern: a regular expression to identify the occurrences to be replaced in the source string
                    - replacement: the value to replace the identified occurrences
                """
                source = disposition.get('source', None)
                if source != None:
                    source = self.expandValue(source, outputDict)
                else:
                    serviceconfig.logger.error('The "source" attribute is not specified in the "template_replace" handler.')
                    serviceconfig.sendMail('ERROR', 'Bad template_replace handler', 'The "source" attribute is not specified in the "template_replace" handler.')
                    self.reportAction(self.filename, 'failure', 'Bad template_replace handler')
                    self.moveFile(self.filename, 'failure', fromDir, dir_cleanup_patterns)
                    results.append('failure')
                    complete = False
                    break
                pattern = disposition.get('pattern', None)
                if pattern != None:
                    pattern = self.expandValue(pattern, outputDict)
                else:
                    serviceconfig.logger.error('The "pattern" attribute is not specified in the "template_replace" handler.')
                    serviceconfig.sendMail('ERROR', 'Bad template_replace handler', 'The "pattern" attribute is not specified in the "template_replace" handler.')
                    self.reportAction(self.filename, 'failure', 'Bad template_replace handler')
                    self.moveFile(self.filename, 'failure', fromDir, dir_cleanup_patterns)
                    results.append('failure')
                    complete = False
                    break
                replacement = disposition.get('replacement', None)
                if replacement != None:
                    replacement = self.expandValue(replacement, outputDict)
                else:
                    serviceconfig.logger.error('The "replacement" attribute is not specified in the "template_replace" handler.')
                    serviceconfig.sendMail('ERROR', 'Bad template_replace handler', 'The "replacement" attribute is not specified in the "template_replace" handler.')
                    self.reportAction(self.filename, 'failure', 'Bad template_replace handler')
                    self.moveFile(self.filename, 'failure', fromDir, dir_cleanup_patterns)
                    results.append('failure')
                    complete = False
                    break
                replace_result = self.basicDict['template_replace'](pattern, source, replacement)
                if replace_result == None:
                    complete = False
                    self.moveFile(self.filename, 'failure', fromDir, dir_cleanup_patterns)
                    results.append('failure')
                    break
                outputDict.update({'replace.result': replace_result})
            elif disposition['handler'] == 'template_pattern':
                """
                Match a string against a pattern.
                If matched:
                    - update the output dictionary with the groups
                    - execute the if_match disposition (if present)
                Else:
                    - execute the if_zero_match disposition (if present) or
                    - reject if the 'failure' attribute is present 
                """
                source = disposition.get('source', None)
                if source != None:
                    source = source % outputDict
                else:
                    serviceconfig.logger.error('The "source" attribute is not specified in the "template_pattern" handler.')
                    serviceconfig.sendMail('ERROR', 'Bad template_pattern handler', 'The "source" attribute is not specified in the "template_pattern" handler.')
                    self.reportAction(self.filename, 'failure', 'Bad template_pattern handler')
                    self.moveFile(self.filename, 'failure', fromDir, dir_cleanup_patterns)
                    results.append('failure')
                    complete = False
                    break
                pattern = disposition.get('pattern', None)
                if pattern != None:
                    pattern = pattern % outputDict
                else:
                    serviceconfig.logger.error('The "pattern" attribute is not specified in the "template_pattern" handler.')
                    serviceconfig.sendMail('ERROR', 'Bad template_pattern handler', 'The "pattern" attribute is not specified in the "template_pattern" handler.')
                    self.reportAction(self.filename, 'failure', 'Bad template_pattern handler')
                    self.moveFile(self.filename, 'failure', fromDir, dir_cleanup_patterns)
                    results.append('failure')
                    complete = False
                    break
                relpath_matching = disposition.get('relpath_matching', False)
                m = self.basicDict['template_match'](pattern, source, relpath_matching)
                if m != None:
                    groups = disposition.get('output', None)
                    if groups == 'groups':
                       for group in m.groupdict():
                           outputDict.update({'%s' % (group): m.group(group)})
                    inner_rule = disposition.get('if_match', None)
                    if inner_rule != None:
                        inner_results = []
                        self.applyDisposition(fromDir, inner_rule, outputDict, True, dir_cleanup_patterns, inner_results)
                        if 'failure' in inner_results:
                            results.append('failure')
                            complete = False
                            break
                else:
                    inner_rule = disposition.get('if_zero_match', None)
                    if inner_rule != None:
                        inner_results = []
                        self.applyDisposition(fromDir, inner_rule, outputDict, True, dir_cleanup_patterns, inner_results)
                        if 'failure' in inner_results:
                            results.append('failure')
                            complete = False
                            break
                    else:
                        failure = disposition.get('failure', None)
                        if failure != None:
                            serviceconfig.logger.error('Zero matches found in the "template_pattern" handler.')
                            serviceconfig.sendMail('ERROR', 'Zero matches found in the template_pattern handler', 'Zero matches found in the template_pattern handler')
                            self.reportAction(self.filename, 'failure', 'Zero matches found in the template_pattern handler')
                            self.moveFile(self.filename, failure, fromDir, dir_cleanup_patterns)
                            results.append('failure')
                            complete = False
                            break
            elif disposition['handler'] == 'rules':
                """
                Execute an inner rule.
                """
                inner_rule = self.findInnerRule(disposition.get('rules', []), fromDir)
                if inner_rule != None:
                    inner_results = []
                    self.applyDisposition(fromDir, inner_rule, outputDict, True, dir_cleanup_patterns, inner_results)
                    if 'failure' in inner_results:
                        results.append('failure')
                        complete = False
                        break
            elif disposition['handler'] == 'sha256':
                """
                Add the checksum of the file.
                """
                prefix = disposition.get('prefix', '') % outputDict
                sha256 = self.basicDict['sha256sum'](self.filename)
                outputDict.update({'%ssha256' % prefix: sha256})
            elif disposition['handler'] == 'md5sum':
                """
                Add the base64 digest string of the file computed with the md5 utility.
                """
                chunk_size = disposition.get('chunk_size', 10000000)
                prefix = disposition.get('prefix', '') % outputDict
                md5sum = self.basicDict['md5sum'](self.filename, chunk_size)
                outputDict.update({'%smd5sum' % prefix: md5sum})
            elif disposition['handler'] == 'md5':
                """
                Add the hexa digest string of the file computed with the md5 utility.
                """
                prefix = disposition.get('prefix', '') % outputDict
                md5hex = self.basicDict['md5hex'](self.filename)
                outputDict.update({'%smd5' % prefix: md5hex})
            elif disposition['handler'] == 'mtime':
                """
                Add the modification time in the specified format.
                """
                prefix = disposition.get('prefix', '') % outputDict
                format = '%Y-%m-%d %H:%M:%S.%f'
                mtime = self.basicDict['mtime'](self.filename)
                outputDict.update({'%smtime' % prefix: datetime.strftime(mtime, format)})
            elif disposition['handler'] == 'urlQuote':
                """
                Add the URL encode values.
                """
                prefix = disposition.get('prefix', '') % outputDict
                resources = disposition['output']
                for resource in resources.keys():
                    value = resources[resource] % outputDict
                    quote = self.basicDict['urlQuote'](value, safe='')
                    outputDict.update({'%s%s' % (prefix, resource): quote})
            elif disposition['handler'] == 'templates':
                """
                Add the templates.
                """
                exists = disposition.get('exists', None)
                if exists != None:
                    hasNone = False
                    for val in exists:
                        try:
                            val1 = val % outputDict
                        except KeyError:
                            val1 = None
                        except:
                            pass
                    
                        if val1 == None:
                            hasNone = True
                            break
                        
                    if hasNone == True:
                        continue
                        
                prefix = disposition.get('prefix', '') % outputDict
                templates = disposition['output']
                for template in templates.keys():
                    try:
                        value = templates[template] % outputDict
                    except:
                        value = templates[template]
                    if value != None:
                        try:
                            if value.startswith('%(') and value.endswith(')s'):
                                value = None
                        except:
                            pass
                    if value == None:
                        try:
                            del outputDict[template]
                        except:
                            pass
                    else:
                        outputDict.update({'%s%s' % (prefix, template): value})
            elif disposition['handler'] == 'datetime':
                """
                Handle date and time types.
                """
                success = False
                prefix = disposition.get('prefix', '') % outputDict
                input = disposition.get('input', None)
                output = disposition.get('output', None)
                if input != None and output != None:
                    input_date_string = input.get('date_string', None)
                    if input_date_string != None:
                        input_format = input.get('format', '%Y-%m-%d %H:%M:%S.%f')
                        try:
                            if 'T' in input_format:
                                """
                                TimeZone in the date.
                                Trim the TimeZone, as Python does not support a format directive for the TimeZone
                                """
                                input_datetime = datetime.strptime((input_date_string % outputDict)[:-6], input_format)
                            else:
                                input_datetime = datetime.strptime(input_date_string % outputDict, input_format)
                            for name in output.keys():
                                output_format = output[name]
                                value = input_datetime.strftime(output_format)
                                outputDict.update({'%s%s' % (prefix, name): value})
                            success = True
                        except:
                            et, ev, tb = sys.exc_info()
                            serviceconfig.logger.error('Bad datetime handler: "%s"' % str(ev))
                            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                            serviceconfig.sendMail('ERROR', 'Handler Processing FAILURE: Bad datetime handler', 'Exception generated during processing the file "%s":\n%s\n%s' % (self.filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                            self.reportAction(self.filename, 'failure', 'Bad datetime handler')
                if success == False:
                    self.moveFile(self.filename, 'failure', fromDir, dir_cleanup_patterns)
                    complete = False
                    results.append('failure')
                    break
                    
            elif disposition['handler'] == 'ermrest':
                """
                Execute an ermrest request.
                """
                
                """
                Check if we have a precondition to execute the ermrest request
                """
                condition = disposition.get('condition', None)
                if condition != None:
                    val1 = condition[0]
                    try:
                        val1 = condition[0] % outputDict
                    except KeyError:
                        val1 = None
                    except:
                        pass
                    
                    val2 = condition[1]
                    try:
                        val2 = condition[1] % outputDict
                    except KeyError:
                        val2 = None
                    except:
                        pass
                    
                    if val1 != val2:
                        continue
                        
                exists = disposition.get('exists', None)
                if exists != None:
                    hasNone = False
                    for val in exists:
                        try:
                            val1 = val % outputDict
                        except KeyError:
                            val1 = None
                        except:
                            pass
                    
                        if val1 == None:
                            hasNone = True
                            break
                        
                    if hasNone == True:
                        continue
                        
                method = disposition.get('method', None)
                warn_on_duplicates = disposition.get('warn_on_duplicates', False)
                unique_columns = disposition.get('unique_columns', [])
                url_path = disposition.get('url_path', None)
                if url_path != None:
                    url_path = url_path % outputDict
                    url = url_path
                else:
                    url = disposition.get('url', None)
                    if url != None:
                        url = url % outputDict
                failure = disposition.get('failure', None)
                webcli = None
                webconn = disposition.get('webconn', None)
                if webconn != None:
                    webcli = self.clients.get(webconn, None)
                if webcli == None or url == None:
                    serviceconfig.sendMail('ERROR', 'ERMREST FAILURE: No Web Connection.', 'Web Connection for ERMREST does not exist.')
                    self.reportAction(self.filename, 'failure', 'Web Connection for ERMREST does not exist')
                    complete = False
                    results.append('failure')
                    self.moveFile(self.filename, failure, fromDir, dir_cleanup_patterns)
                    break
                    
                body = []
                ignoreErrorCodes = []
                continueAfter = disposition.get('continueAfter', [])
                if method == 'POST' or method == 'PUT' and '/entity/' in url:
                    """
                    Build the POST body.
                    """
                    colmap = disposition.get('colmap', {})
                    cols = dict()
                    for col in colmap.keys():
                        try:
                            value = colmap[col] % outputDict
                        except:
                            value = colmap[col]
                            if value != None:
                                try:
                                    if value.startswith('%(') and value.endswith(')s'):
                                        value = None
                                except:
                                    pass
                        cols.update({col: value})
                    """
                    Add the missing columns with NULL values
                    """
                    columns_url = self.getTableColumnsURL(self.basicDict['urlPath'](url, url_path))
                    if columns_url != None and webcli != None:
                        status = 'failure'
                        try:
                            resp = webcli.send_request('GET', '%s/' % (columns_url), headers={'Content-Type': 'application/json'}, webapp='ERMREST')
                            rows = json.load(resp)
                            defaults = []
                            for row in rows:
                                if row['name'] not in cols.keys() and row['name'] not in self.system_colnames:
                                    cols.update({row['name']: None})
                                    defaults.append(self.basicDict['urlQuote'](row['name'], safe=''))
                            if len(defaults) > 0:
                                url = '%s?defaults=%s' % (url, ','.join(defaults))
                        except ErmrestHTTPException, e:
                            complete = False
                            if e.status in [0, REQUEST_TIMEOUT, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT] or e.retry==True:
                                failure = 'retry'
                                status = 'retry'
                                status_code = e.status
                        except:
                            complete = False
                            et, ev, tb = sys.exc_info()
                            serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                        if complete==False:
                            results.append('failure')
                            self.reportAction(self.filename, status, '%d' % status_code)
                            self.moveFile(self.filename, failure, fromDir, dir_cleanup_patterns)
                            break

                    body.append(cols)
                    json_body = body
                    body = self.json2csv(body)
                    serviceconfig.logger.debug("Entity body: %s" % body)
                elif method == 'PUT' and '/attributegroup/' in url:
                    serviceconfig.logger.debug("PUT url: %s" % url)
                    """
                    Build the PUT body.
                    """
                    cols = dict()
                    colmap = disposition.get('colmap', {})
                    """
                    Remove from the dictionary the columns with NULL values
                    """
                    for col in colmap.keys():
                        try:
                            value = outputDict[col]
                            if value == None:
                                del outputDict[col]
                        except:
                            pass
                    for col in colmap.keys():
                        try:
                            value = colmap[col] % outputDict
                        except:
                            value = colmap[col]
                            if value != None:
                                try:
                                    if value.startswith('%(') and value.endswith(')s'):
                                        value = None
                                except:
                                    pass
                        cols.update({col: value})
                    body.append(cols)
                    body = self.json2csv(body)
                    serviceconfig.logger.debug("PUT body: %s" % body)
                elif method == 'GET':
                    """
                    The GET request should return only 1 row.
                    An error should be reported if it returns more then 1 row.
                    The column names and values from the returned row should
                    be stored in the outputDict
                    """
                    try:
                        resp = webcli.send_request('GET', self.basicDict['urlPath'](url, url_path), headers={'Content-Type': 'application/json'}, webapp='ERMREST')
                        rows = json.load(resp)
                        self.updateDictionary(rows, outputDict)
                        if len(rows) != 1:
                            serviceconfig.logger.debug('GET request "%s" for file "%s" has returned %d rows' % (url, self.filename, len(rows)))
                            if '*' not in continueAfter and (len(rows) != 0 or 'ZERO_RESULT' not in continueAfter):
                                serviceconfig.sendMail('ERROR', 'ERMREST GET FAILURE: Invalid number of rows returned', 'GET request "%s" for file "%s" has returned %d rows' % (url, self.filename, len(rows)))
                                self.reportAction(self.filename, 'failure', 'Invalid number of rows returned by the GET request')
                                complete = False
                    except ErmrestHTTPException, e:
                        if '*' not in continueAfter and e.status not in continueAfter:
                            complete = False
                            status = 'failure'
                            if e.status in [0, REQUEST_TIMEOUT, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT] or e.retry==True:
                                failure = 'retry'
                                status = 'retry'
                            serviceconfig.sendMail('ERROR', 'ERMREST GET FAILURE: %d' % e.status, 'Error generated during the %s request "%s" for the file "%s":\n%s' % (method, url, self.filename, str(e)))
                            self.reportAction(self.filename, status, '%d' % e.status)
                    except:
                        complete = False
                        et, ev, tb = sys.exc_info()
                        serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                        self.reportAction(self.filename, 'failure', str(et))
                    if complete==False:
                        results.append('failure')
                        self.moveFile(self.filename, failure, fromDir, dir_cleanup_patterns)
                        break
                    else:
                        serviceconfig.sendMail('INFO', 'ERMREST GET SUCCESS', '%s: %s' % (method, url))
                        
                if webcli and (method == 'POST' or method == 'PUT'):
                    """
                    Send the ermrest request
                    """
                    success=False
                    try:
                        if method in ['POST', 'PUT']:
                            headers = {'Content-Type': 'text/csv', 'Accept': 'application/json'}
                        else:
                            headers = {'Content-Type': 'application/json'}
                            body = json.dumps(body)
                        if method == 'POST':
                            ignoreErrorCodes = []
                        resp = webcli.send_request(method, self.basicDict['urlPath'](url, url_path), body, headers, ignoreErrorCodes=ignoreErrorCodes, webapp='ERMREST')
                        #resp.read()
                        rows = json.load(resp)
                        self.updateDictionary(rows, outputDict)
                        success = True
                        serviceconfig.sendMail('INFO', 'ERMREST %s SUCCESS' % method, '%s: %s\n%s' % (method, url, body))
                    except ErmrestHTTPException, e:
                        if method == 'POST' and e.status == CONFLICT:
                            """
                            Check if the CONFLICT is due to duplicates
                            """
                            try:
                                url = self.basicDict['urlPath'](url, url_path)
                                if len(unique_columns)==0:
                                    """
                                    Unique columns are not specified in the ermrest handler.
                                    Get them from the introspection.
                                    """
                                    unique_url = self.getTableUniqueKeysURL(url)
                                    if unique_url!=None:
                                        resp = webcli.send_request('GET', '%s/' % (unique_url), headers={'Content-Type': 'application/json'}, webapp='ERMREST')
                                        rows = json.load(resp)
                                        for row in rows:
                                            unique_columns.extend(row['unique_columns'])
                                if len(unique_columns)>0:
                                    """
                                    Remove the parameters from the query URL
                                    """
                                    index = url.find('?')
                                    if index > 0:
                                        url = url[0:index]
                                    resp = webcli.send_request('GET', '%s/%s' % (url, self.getBodyPredicate(unique_columns, json_body)), headers={'Content-Type': 'application/json'}, webapp='ERMREST')
                                    rows = json.load(resp)
                                    rowsCount = len(rows)
                                    if rowsCount > 0:
                                        serviceconfig.logger.info('Bypassing the CONFLICT error due to the existence of %d duplicate(s).' % rowsCount)
                                        if warn_on_duplicates==True or 'WARNING' in serviceconfig.getMailActions():
                                            serviceconfig.sendMail('ANY', 'ERMREST POST WARNING: Duplicate found', 'Found duplicate entry in ermrest for the file "%s". The POST CONFLICT error will be ignored.' % (self.filename))
                                            self.reportAction(self.filename, 'duplicate', 'ERMREST Duplicate')
                                        success = True
                            except ErmrestHTTPException, e:
                                if '*' in continueAfter or e.status in continueAfter:
                                    success = True
                                elif e.status in [0, REQUEST_TIMEOUT, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT] or e.retry==True:
                                    failure = 'retry'
                                    self.reportAction(self.filename, 'retry', 'ERMREST Transient Error')
                            except:
                                et, ev, tb = sys.exc_info()
                                serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                                self.reportAction(self.filename, 'failure', str(et))
                        else:
                            if '*' in continueAfter or e.status in continueAfter:
                                success = True
                            else:
                                status = 'failure'
                                if e.status in [0, REQUEST_TIMEOUT, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT] or e.retry==True:
                                    failure = 'retry'
                                    status = 'retry'
                                serviceconfig.sendMail('ERROR', 'ERMREST FAILURE %d' % e.status, 'Error generated during the %s request: %s\n%s' % (method, url, str(e)))
                                self.reportAction(self.filename, status, '%d' % e.status)
                    except:
                        et, ev, tb = sys.exc_info()
                        serviceconfig.sendMail('ERROR', 'ERMREST FAILURE: %s' % str(et), 'Exception generated during the %s request: %s\n%s\n%s' % (method, url, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                        self.reportAction(self.filename, 'failure', str(et))
                    if success==False and failure:
                        serviceconfig.logger.debug("failure action: %s" % failure)
                    if success==False:
                        complete = False
                        results.append('failure')
                        self.moveFile(self.filename, failure, fromDir, dir_cleanup_patterns)
                        break
            elif disposition['handler'] == 'hatrac':
                """
                Upload the file.
                """
                metadata = disposition.get('metadata', {}).copy()
                if len(metadata) == 0:
                    checksum = disposition.get('checksum', [])
                    if 'md5' not in checksum:
                        checksum.append('md5')
                    metadata.update({"checksum": checksum})
                    content_disposition = disposition.get('content_disposition', None)
                    if content_disposition != None:
                        content_disposition = content_disposition % outputDict
                        metadata.update({"content_disposition": content_disposition})
                else:
                    checksum = metadata.get('checksum', [])
                    if 'md5' not in checksum:
                        checksum.append('md5')
                    metadata.update({"checksum": checksum})
                    content_disposition = metadata.get('content_disposition', None)
                    if content_disposition != None:
                        content_disposition = content_disposition % outputDict
                        metadata.update({"content_disposition": content_disposition})
                warn_on_duplicates = disposition.get('warn_on_duplicates', False)
                object_url = disposition.get('url_path', None)
                if object_url != None:
                    object_url = object_url % outputDict
                    url = object_url
                    o = urlparse.urlparse(url)
                else:
                    url = disposition.get('url', None)
                    if url != None:
                        url = url % outputDict
                        o = urlparse.urlparse(url)
                        object_url = o.path
                chunk_size = disposition.get('chunk_size', 10000000)
                failure = disposition.get('failure', None)
                webcli = None
                webconn = disposition.get('webconn', None)
                if webconn != None:
                    webcli = self.clients.get(webconn, None)
                if webcli == None or object_url == None:
                    serviceconfig.sendMail('ERROR', 'HATRAC FAILURE: No Web Connection.', 'Web Connection for HATRAC does not exist.')
                    self.reportAction(self.filename, 'failure', 'Web Connection for HATRAC does not exist')
                    complete = False
                    results.append('failure')
                    self.moveFile(self.filename, failure, fromDir, dir_cleanup_patterns)
                    break
                    
                if webcli.get_md5sum(object_url) == self.basicDict['md5sum'](self.filename, chunk_size):
                    serviceconfig.logger.info('Skipping the upload of the file "%s" as it has the same md5sum as the one from hatrac.' % self.filename)
                    hatrac_location = webcli.getHatracLocation(object_url)
                    outputDict.update({'hatrac_location': hatrac_location})
                    serviceconfig.logger.debug('hatrac_location: "%s"' % (outputDict['hatrac_location']))
                    if warn_on_duplicates==True or 'WARNING' in serviceconfig.getMailActions():
                        serviceconfig.sendMail('ANY', 'HATRAC WARNING: Duplicate found', 'Skipping the upload of the file "%s" as it has the same md5sum as the one from hatrac.' % self.filename)
                        self.reportAction(self.filename, 'duplicate', 'HATRAC Duplicate')
                    continue
                
                create_parents = disposition.get('create_parents', False)
                pathes = o.path.split('/')[:-1]
                namespaces = pathes[2:]
                try:
                    res = webcli.retrieveNamespace('/'.join(pathes))
                except:
                    et, ev, tb = sys.exc_info()
                    serviceconfig.sendMail('ERROR', 'HATRAC FAILURE: Can not retrieve namespace', 'Can not retrieve namespace "%s"\n. Error: "%s"' % ('/'.join(pathes), ''.join(traceback.format_exception(et, ev, tb))))
                    raise
                    
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
                                    status = 'failure'
                                    if e.retry==True:
                                        failure = 'retry'
                                        status = 'retry'
                                    success = False
                                    serviceconfig.sendMail('ERROR', 'HATRAC FAILURE: Can not create namespace', 'ErmrestHTTPException: Can not create namespace "%s"\n. Error: "%s"' % ('/'.join(urls), str(e)))
                                    self.reportAction(self.filename, status, 'Can not create namespace')
                                    break
                                except:
                                    success = False
                                    break
                        if success == False:
                            complete = False
                            results.append('failure')
                            self.moveFile(self.filename, failure, fromDir, dir_cleanup_patterns)
                            break
                    else:
                        serviceconfig.logger.debug('Can not upload the file "%s". The namespace "%s" does not exist and the "create_parents" option is not set to "true".' % (self.filename, '/'.join(namespaces)))
                        serviceconfig.sendMail('ERROR', 'HATRAC FAILURE: Namespace does not exist', 'Namespace "%s" does not exist and the option "create_parents" is not set to "true".' % '/'.join(namespaces))
                        self.reportAction(self.filename, 'failure', 'Namespace does not exist')
                        complete = False
                        results.append('failure')
                        self.moveFile(self.filename, failure, fromDir, dir_cleanup_patterns)
                        break
                try:
                    job_id, status, hatrac_location = webcli.uploadFile(object_url, self.filename, chunk_size, metadata)
                    outputDict.update({'hatrac_location': hatrac_location})
                    serviceconfig.logger.debug('hatrac_location: "%s"' % (hatrac_location))
                    serviceconfig.sendMail('INFO', 'HATRAC SUCCESS', 'File "%s" was uploaded at "%s"' % (self.filename, object_url))
                except:
                    et, ev, tb = sys.exc_info()
                    serviceconfig.logger.error('Can not transfer file "%s" in namespace "%s". Error: "%s"' % (self.filename, object_url, str(ev)))
                    complete = False
                    results.append('failure')
                    self.moveFile(self.filename, failure, fromDir, dir_cleanup_patterns)
                    serviceconfig.sendMail('ERROR', 'HATRAC FAILURE: %s' % str(et), 'Can not upload file "%s" in namespace "%s". Error: "%s"' % (self.filename, object_url, str(ev)))
                    self.reportAction(self.filename, 'failure', 'Can not upload file')
                    break
        if complete == True and isInnerRule == False:
            self.moveFile(self.filename, 'success', fromDir, dir_cleanup_patterns)

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
            if e.winerror == winerror.ERROR_SHARING_VIOLATION or e.winerror == winerror.ERROR_FILE_NOT_FOUND:
                return False
            else:
                #et, ev, tb = sys.exc_info()
                #serviceconfig.logger.error('got WindowsError on checking if the file "%s" is ready for procesing.' % str(ev))
                #serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                return None
        except IOError,e:
            if e.errno == errno.EACCES:
                return False
            else:
                #et, ev, tb = sys.exc_info()
                #serviceconfig.logger.error('got IOError on checking if the file "%s" is ready for procesing.' % str(ev))
                #serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
                #serviceconfig.sendMail('ERROR', 'File Processing FAILURE: %s' % str(et), 'Exception generated during on checking if the new file "%s" is ready:\n%s\n%s' % (filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
                #self.reportAction(self.filename, 'failure', str(et))
                return None
        except:
            #et, ev, tb = sys.exc_info()
            #serviceconfig.logger.error('got Exception on checking if the file "%s" is ready for procesing.' % str(ev))
            #serviceconfig.logger.error('%s' % str(traceback.format_exception(et, ev, tb)))
            #serviceconfig.sendMail('ERROR', 'File Processing FAILURE: %s' % str(et), 'Exception generated during on checking if the new file "%s" is ready:\n%s\n%s' % (filename, str(ev), ''.join(traceback.format_exception(et, ev, tb))))
            #self.reportAction(self.filename, 'failure', str(et))
            return None

    """
    Move the file into a directory based on the process result.
    """
    def moveFile(self, filename, action, fromDir, dir_cleanup_patterns):
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
        
        """
        do nothing if destination is unchanged 
        """
        if fromDir == toDir:
            serviceconfig.logger.info('File: "%s" remains on the "%s" directory.' % (filename, toDir))
            return
        
        """
        get the relative path of the filename parent
        """
        dirnameParts = os.path.dirname(filename).split(os.sep)
        fromDirParts = fromDir.split(os.sep)
        dirnameParts = dirnameParts[len(fromDirParts):]
        
        """
        set the path of the destination directory
        """
        toDir = [toDir]
        toDir.extend(dirnameParts)
        toDir = os.sep.join(toDir)
        
        if os.path.exists(toDir) == False:
            os.makedirs(toDir)
        if os.path.isfile('%s%s%s' % (toDir, os.sep, os.path.basename(filename))):
            os.remove('%s%s%s' % (toDir, os.sep, os.path.basename(filename)))
        serviceconfig.logger.info('Moved file: "%s" to the "%s" directory.' % (filename, toDir))
        os.rename(filename, '%s%s%s' % (toDir, os.sep, os.path.basename(filename)))
        time.sleep(1)
        serviceconfig.sendMail('INFO', 'File Processing %s' % (subject), 'The file "%s" was moved to the "%s" directory.' % (os.path.basename(filename), action))
        if action == 'success':
            self.reportAction(filename, 'success')
        self.cleanDirectory(fromDir, dirnameParts, dir_cleanup_patterns)
    
    """
    Remove empty directories from the fromDir
    """
    def cleanDirectory(self, fromDir, dirnameParts, dir_cleanup_patterns):
        if len(dirnameParts) > 0:
            dirname = '%s%s%s' % (fromDir,os.sep,os.sep.join(dirnameParts))
            dir_relpath = '/'.join(dirnameParts)
            if len(os.listdir(dirname)) == 0:
                for pattern in dir_cleanup_patterns:
                    if re.search(pattern, dir_relpath):
                        os.rmdir(dirname)
                        time.sleep(1)
                        self.cleanDirectory(fromDir, dirnameParts[:-1], dir_cleanup_patterns)
                        break
            
    """
    Convert a JSON body to CSV
    """
    def json2csv(self, body):
        rows = []
        columns = body[0].keys()
        row = []
        for col in columns:
            row.append('"%s"' % col.replace('"', '""'))
        rows.append(','.join(row))
        for row in body:
            values = []
            for col in columns:
                if row[col] != None:
                    values.append('"%s"' % str(row[col]).replace('"', '""'))
                else:
                    values.append('')
            rows.append(','.join(values))
        return '\n'.join(rows)
        
    """
    Get the body predicate
    """
    def getBodyPredicate(self, unique_columns, body):
        rows = []
        row = body[0]
        for col in unique_columns:
            if row[col] != None:
                rows.append('%s=%s' % (self.basicDict['urlQuote'](col, safe=''), self.basicDict['urlQuote'](str(row[col]), safe='')))
        return '&'.join(rows)
        
    """
    Get the unique keys URL of the POST request
    """
    def getTableUniqueKeysURL(self, url):
        ret = None
        index = url.find('/entity/')
        if index > 0:
            url_prefix = url[0:index]
            index1 = index + len('/entity/')
            index2 = url.find('?')
            if index2 < 0:
                index2 = len(url)
            entity = url[index1:index2].split(':')
            if len(entity)==2:
                schema = entity[0]
                table = entity[1]
                ret = '%s/schema/%s/table/%s/key' % (url_prefix, schema, table)
        return ret
        
    """
    Get the columns URL of the table referred in the POST request
    """
    def getTableColumnsURL(self, url):
        ret = None
        index = url.find('/entity/')
        if index > 0:
            url_prefix = url[0:index]
            index1 = index + len('/entity/')
            index2 = url.find('?')
            if index2 < 0:
                index2 = len(url)
            entity = url[index1:index2].split(':')
            if len(entity)==2:
                schema = entity[0]
                table = entity[1]
                ret = '%s/schema/%s/table/%s/column' % (url_prefix, schema, table)
        return ret
        
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

    
