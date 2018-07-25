*** Dockerfile.opensuse-tumbleweed-rpm ***

Completely RPM based installation of web2ldap on openSUSE Tumbleweed.

*** Dockerfile.opensuse-tumbleweed-venv ***

RPM based installation of Python modules on openSUSE Tumbleweed and
web2ldap in virtual env with --system-site-packages.

*** Build and run the container ***

docker build --tag web2ldap:tumbleweed --file Dockerfile.opensuse-tumbleweed-rpm .

docker run -p 1760:1760 web2ldap:tumbleweed

curl http://localhost:1760/web2ldap/monitor|html2text
