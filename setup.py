#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
package/install module package ekca-client
"""

import sys
import os
from setuptools import setup, find_packages

PYPI_NAME = 'web2ldap'

BASEDIR = os.path.dirname(os.path.realpath(__file__))

sys.path.insert(0, os.path.join(BASEDIR, 'web2ldap'))
import __about__

setup(
    name=PYPI_NAME,
    license=__about__.__license__,
    version=__about__.__version__,
    description='web2ldap',
    long_description='Web-based LDAPv3 client application',
    author=__about__.__author__,
    author_email=__about__.__mail__,
    maintainer=__about__.__author__,
    maintainer_email=__about__.__mail__,
    url='https://www.web2ldap.de',
    download_url='https://www.web2ldap.de/download.html',
    keywords=['LDAP', 'LDAPv3', 'Web', 'Gateway'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: Database :: Front-Ends',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: System :: Systems Administration',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
    ],
    packages=find_packages(exclude=['tests']),
    package_dir={'': '.'},
    test_suite='tests',
    python_requires='==2.7.*',
    include_package_data=True,
    install_requires=[
        'setuptools',
        'ldap0>=0.0.55',
        'pyweblib',
        'ipaddress',
        'M2Crypto',
        'pyExcelerator',
        'pydns',
        'paramiko',
        'Pillow',
    ],
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'web2ldap-fcgi=web2ldap.fcgiserver:start',
            'web2ldap-http=web2ldap.standalone:start',
            'web2ldap-checkinst=web2ldap.checkinst:check_inst',
        ],
    }
)
