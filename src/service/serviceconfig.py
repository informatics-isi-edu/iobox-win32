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
Load configuration for the Ermrest Outbox.
"""

import os
import logging
import json
import sys
import traceback

is_win32 = False
    
import observer
from logging.handlers import RotatingFileHandler    
import smtplib
from email import Encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

FORMAT = '%(asctime)s: %(levelname)s <%(module)s>: %(message)s'
logger = logging.getLogger(__name__)
mail_server = None
mail_sender = None
mail_receiver = None
mail_footer = 'Do not reply to this message.  This is an automated message generated by the system, which does not receive email messages.'

_report_mail = """
As of %(today)s there are:

%(success)d success file(s)
%(failure)d failure case(s)
%(duplicate)d duplicate(s)
%(retry)d retry(ies)

The attached file contains a detailed report.

"""
error_message = None

# Exit return codes
__EXIT_SUCCESS = 0
__EXIT_FAILURE = 1

# Used by ArgumentParser
__BULK_OPS_MAX = 1000

# Loglevel dictionary
__LOGLEVEL = {'error': logging.ERROR,
              'warning': logging.WARNING,
              'info': logging.INFO,
              'debug': logging.DEBUG}

# Mail Message
mail_actions = ['ERROR',
                'WARNING',
                'NOTICE',
                'INFO']

def load(config_filename=None):
    """
    Read the configuration file and initialize the service.
    """
    global is_win32
    
    if config_filename == None:
        """
        Use home directory as default location for outbox.conf
        """
        is_win32 = True
        default_config_filename = os.path.join(
                os.path.expanduser('~'), 'Documents', 'iobox', 'config', 'outbox.conf')
    else:
        default_config_filename = config_filename
    
    """
    Load configuration file
    """
    global logger, mail_server, mail_sender, mail_receiver, error_message, mail_actions
    hasLogger = False
    cfg = {}
    if os.path.exists(default_config_filename):
        f = open(default_config_filename, 'r')
        try:
            cfg = json.load(f)
            loglevel = cfg.get('loglevel', None)
            logfile = cfg.get('log', None)
            if loglevel and logfile:
                rotatingFileHandler = RotatingFileHandler(logfile, maxBytes=1000000, backupCount=7)
                rotatingFileHandler.setFormatter(logging.Formatter(FORMAT))
                logger.addHandler(rotatingFileHandler)
                logger.setLevel(__LOGLEVEL.get(loglevel))
                hasLogger = True
            else:
                logging.getLogger().addHandler(logging.NullHandler())
            logger.debug("config: %s" % cfg)
        except ValueError as e:
            if hasLogger == False:
                serviceLogFile = os.path.join(os.path.expanduser('~'), 'Documents', 'iobox_service.log')
                rotatingFileHandler = RotatingFileHandler(serviceLogFile, maxBytes=1000000, backupCount=7)
                rotatingFileHandler.setFormatter(logging.Formatter(FORMAT))
                logger.addHandler(rotatingFileHandler)
                logger.setLevel(__LOGLEVEL.get('debug'))
            error_message = 'Malformed configuration file: %s' % e
            logger.error(error_message)
            return None
        else:
            f.close()
    else:
        serviceLogFile = os.path.join(os.path.expanduser('~'), 'Documents', 'iobox_service.log')
        rotatingFileHandler = RotatingFileHandler(serviceLogFile, maxBytes=1000000, backupCount=7)
        rotatingFileHandler.setFormatter(logging.Formatter(FORMAT))
        logger.addHandler(rotatingFileHandler)
        logger.setLevel(__LOGLEVEL.get('debug'))
        error_message = 'Configuration file: "%s" does not exist.' % default_config_filename
        logger.error(error_message)
        return None
    
    """ 
    Global settings 
    """
    mail_cfg = cfg.get('mail', None)
    if mail_cfg != None:
        mail_server = mail_cfg.get('server', None)
        mail_sender = mail_cfg.get('sender', None)
        mail_receiver = mail_cfg.get('receiver', None)
        mail_actions = mail_cfg.get('actions', mail_actions)
    timeout = cfg.get('timeout', 30)
    monitored_dirs = cfg.get('monitored_dirs', None)
    report = cfg.get('report', None)
    connections = cfg.get('connections', None)
    if monitored_dirs:
        observerManager = observer.ObserverManager(mail_server=mail_server, \
                                                  mail_sender=mail_sender, \
                                                  mail_receiver=mail_receiver, \
                                                  timeout=timeout, \
                                                  report=report, \
                                                  connections=connections, \
                                                  monitored_dirs=monitored_dirs)
        return observerManager.load()
    else:
        return None
    
def sendMail(message, subject, text):
    global logger, mail_server, mail_sender, mail_receiver, mail_actions
    
    if mail_server and mail_sender and mail_receiver and (message in mail_actions or message=='ANY'):
        try:
            msg = MIMEText('%s\n\n%s' % (text, mail_footer), 'plain')
            msg['Subject'] = 'IOBox %s' % subject
            msg['From'] = mail_sender
            msg['To'] = mail_receiver
            s = smtplib.SMTP(mail_server)
            s.sendmail(mail_sender, mail_receiver.split(','), msg.as_string())
            s.quit()
            logger.debug('Sent email notification: %s' % text)
        except:
            et, ev, tb = sys.exc_info()
            logger.error('got exception "%s"' % str(ev))
            logger.error('%s' % str(traceback.format_exception(et, ev, tb)))

def sendReport(subject, report):
    global logger, mail_server, mail_sender, mail_receiver
    
    if mail_server and mail_sender and mail_receiver:
        try:
            outer = MIMEMultipart()
            outer['Subject'] = 'IOBox %s' % subject
            outer['From'] = mail_sender
            outer['To'] = mail_receiver
            
            msg = MIMEText('%s\n\n\n\n%s' % ((_report_mail % (dict(success=report.get('success', 0), failure=report.get('failure', 0), duplicate=report.get('duplicate', 0), retry=report.get('retry', 0), today=report.get('today', 'YYYY-MM-DD')))), mail_footer), 'plain')
            outer.attach(msg)
            
            fp = open('%s%s%s' % (report.get('output'), os.sep, report.get('file')), 'rb')
            msg = MIMEBase('application', 'octet-stream')
            msg.set_payload(fp.read())
            fp.close()
            Encoders.encode_base64(msg)
            msg.add_header('Content-Disposition', 'attachment', filename=report.get('file'))
            outer.attach(msg)
            
            s = smtplib.SMTP(mail_server)
            s.sendmail(mail_sender, outer['To'].split(','), outer.as_string())
            s.quit()
            logger.debug('Sent email notification: %s' % _report_mail % (dict(success=report.get('success', 0), failure=report.get('failure', 0), duplicate=report.get('duplicate', 0), retry=report.get('retry', 0), today=report.get('today', 'YYYY-MM-DD'))))
        except:
            et, ev, tb = sys.exc_info()
            logger.error('got exception "%s"' % str(ev))
            logger.error('%s' % str(traceback.format_exception(et, ev, tb)))

def getLogErrorMsg():
    global error_message

    return error_message

def getMailActions():
    global mail_actions

    return mail_actions

def isWin32():
    global is_win32

    return is_win32

