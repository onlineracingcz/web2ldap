docker build --tag web2ldap:tumbleweed --file Dockerfile.opensuse-tumbleweed .

docker run -p 1760:1760 web2ldap-opensuse-tumbleweed

curl http://localhost:1760/web2ldap/monitor|html2text
