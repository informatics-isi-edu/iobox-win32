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
Load configuration for the Ermrest Outbox.
"""

import os
import logging
import json

from client import ErmrestClient, UnresolvedAddress, NetworkError, ProtocolError, MalformedURL
from observer import CirmObserver
from logging.handlers import RotatingFileHandler    

FORMAT = '%(asctime)s: %(levelname)s <%(module)s>: %(message)s'
logger = logging.getLogger(__name__)

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
    
    # Use home directory as default location for outbox.conf
    default_config_filename = os.path.join(
            os.path.expanduser('~'), 'Documents', 'scans', 'config', 'outbox.conf')
    
    # Load configuration file, or create configuration based on arguments
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
    
    # Ermrest settings
    url = cfg.get('url', None)
    if not url:
        logger.error('Ermrest URL must be given.')
        return None
    
    http_url = cfg.get('http_url', None)
    if not http_url:
        logger.error('Scan HTTP URL ROOT must be given.')
        return None
    
    goauthtoken = cfg.get('goauthtoken', None)
    bulk_ops_max = int(cfg.get('bulk_ops_max', __BULK_OPS_MAX))
    
    inbox = cfg.get('inbox', None)
    if not inbox:
        logger.error('Inbox directory must be given.')
        return None

    outbox = cfg.get('outbox', None)
    if not outbox:
        logger.error('Outbox directory must be given.')
        return None

    rejected = cfg.get('rejected', None)
    if not rejected:
        logger.error('Rejected directory must be given.')
        return None

    username = cfg.get('username', None)
    if not username:
        logger.error('Ermrest username must be given.')
        return None
        
    password = cfg.get('password', None)
    if not password:
        logger.error('Ermrest password must be given.')
        return None

    pattern = cfg.get('pattern', None)
    if not pattern:
        logger.error('Filename pattern must be given.')
        return None

    endpoint_1 = cfg.get('endpoint_1', None)
    if not endpoint_1:
        logger.error('Source endpoint must be given.')
        return None

    endpoint_2 = cfg.get('endpoint_2', None)
    if not endpoint_2:
        logger.error('Destination endpoint must be given.')
        return None

    # Establish Ermrest client connection
    try:
        client = ErmrestClient(url, username, 
                            password, endpoint_1, endpoint_2, goauthtoken)
        client.connect()
    except MalformedURL as err:
        logger.error(err)
        return None
    except UnresolvedAddress as err:
        logger.error(err)
        return None
    except NetworkError as err:
        logger.error(err)
        return None
    except ProtocolError as err:
        logger.error(err)
        return None
    except Exception as err:
        logger.error(err)
        return None
    
    return CirmObserver(url=url, \
                              inbox=inbox, \
                              outbox=outbox, \
                              rejected=rejected, \
                              pattern=pattern, \
                              bulk_ops_max=bulk_ops_max, \
                              http_url=http_url, \
                              client=client)

