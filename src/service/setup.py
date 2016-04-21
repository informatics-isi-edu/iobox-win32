from distutils.core import setup
import py2exe


setup(
    name = 'IOBox',
    description = 'IOBox service for registering files',
    version = '1.00.00',
    service = ['IOBoxObserverService'],
    zipfile=None,
)
