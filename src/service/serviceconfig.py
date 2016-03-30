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

import observer
from logging.handlers import RotatingFileHandler    
import smtplib
from email.mime.text import MIMEText

FORMAT = '%(asctime)s: %(levelname)s <%(module)s>: %(message)s'
logger = logging.getLogger(__name__)
mail_server = None
mail_sender = None
mail_receiver = None
mail_footer = 'Do not reply to this message.  This is an automated message generated by the system, which does not receive email messages.'

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

def load():
    """
    Read the configuration file and initialize the service.
    """
    
    """
    Use home directory as default location for outbox.conf
    """
    default_config_filename = os.path.join(
            os.path.expanduser('~'), 'Documents', 'iobox', 'config', 'outbox.conf')
    
    """
    Load configuration file
    """
    global logger, mail_server, mail_sender, mail_receiver
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
            else:
                logging.getLogger().addHandler(logging.NullHandler())
            logger.debug("config: %s" % cfg)
        except ValueError as e:
            logger.error('Malformed configuration file: %s' % e)
            return None
        else:
            f.close()
    else:
        logger.error('Configuration file: "%s" does not exist.' % default_config_filename)
        return None
    
    """ 
    Global settings 
    """
    mail_server = cfg.get('mail_server', None)
    mail_sender = cfg.get('mail_sender', None)
    mail_receiver = cfg.get('mail_receiver', None)
    timeout = cfg.get('timeout', 30)
    monitored_dirs = cfg.get('monitored_dirs', None)
    if monitored_dirs:
        observerManager = observer.ObserverManager(mail_server=mail_server, \
                                                  mail_sender=mail_sender, \
                                                  mail_receiver=mail_receiver, \
                                                  timeout=timeout, \
                                                  monitored_dirs=monitored_dirs)
        return observerManager.load()
    else:
        return None
    
def sendMail(subject, text):
    global logger, mail_server, mail_sender, mail_receiver
    
    if mail_server and mail_sender and mail_receiver:
        try:
            msg = MIMEText('%s\n\n%s' % (text, mail_footer), 'plain')
            msg['Subject'] = subject
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

