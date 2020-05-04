*** Dockerfile.opensuse-tumbleweed-rpm ***

Completely RPM based installation of web2ldap on openSUSE Tumbleweed.

*** Dockerfile.opensuse-tumbleweed-venv ***

RPM based installation of build tools on openSUSE Tumbleweed and
pip installation of web2ldap in virtual env with --system-site-packages.

*** Dockerfile.opensuse-tumbleweed-venv ***

apt based installation of build tools on openSUSE Tumbleweed and
pip installation of web2ldap in virtual env with --system-site-packages.

*** Build and run the container ***

docker build --tag web2ldap --file Dockerfile.<flavor> .

docker run -p 1760:1760 web2ldap

curl http://172.17.0.1:1760/web2ldap/monitor|html2text
