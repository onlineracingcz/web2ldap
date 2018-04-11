#!/usr/bin/python2
# -*- coding: utf-8 -*-
"""
package/install module package ekca-client
"""

import sys
import os
import glob
from setuptools import setup, find_packages

PYPI_NAME = 'web2ldap'

BASEDIR = os.path.dirname(os.path.realpath(__file__))

data_files=sorted([
    (
        root_dir[len(BASEDIR)+1:],
        [
            os.path.join(root_dir[len(BASEDIR)+1:], filename)
            for filename in filenames
        ]
    )
    for root_dir, _, filenames in os.walk(os.path.join(BASEDIR, 'etc/web2ldap'))
])

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
    data_files=data_files,
    install_requires=[
        'setuptools',
        'ldap0>=0.0.60',
        'pyweblib',
        'ipaddress',
        'asn1crypto',
        'xlwt',
        'pydns',
        'paramiko',
        'Pillow',
        'certifi',
    ],
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'web2ldap=web2ldap.wsgi:start_server',
            'web2ldap-checkinst=web2ldap.checkinst:check_inst',
        ],
        'web2ldap_data': [
            'templates=web2ldapcnf.templates:get_templates_path',
            'properties=web2ldapcnf.templates:get_properties_path',
            'schema=web2ldapcnf.templates:get_schema_path',
        ],
    }
)
