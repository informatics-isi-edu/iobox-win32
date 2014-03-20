from distutils.core import setup
import py2exe


setup(
    name = 'CIRM IOBox',
    description = 'CIRM service for registering files',
    version = '1.00.00',
    service = ['CirmObserverService'],
    zipfile=None,
)
