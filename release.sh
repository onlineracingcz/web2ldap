#!/bin/bash

# Don't use uninitialized vars
set -o nounset
# Set strict umask
umask 077

# remove all temporary stuff
./clean.sh

# After here exit on any error
set -e

# determine version numer
RELEASE=$(PYTHONPATH=$(pwd)/web2ldap python3 -c 'from __about__ import __version__ ; print(__version__)')

echo "Will tag and publish ${RELEASE} now..."

# push and tag the git repo
git push
git tag -s -m "release ${RELEASE}" "v${RELEASE}"
git push --tags

# build source distribution and push to PyPI
# (release defined in setup.cfg)
python3 setup.py release

mv -iv dist/web2ldap* $HOME/Proj/releases/web2ldap/
