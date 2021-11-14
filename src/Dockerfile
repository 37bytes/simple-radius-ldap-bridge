FROM python:3.9

WORKDIR /server/
ADD dictionary dictionary.freeradius server.py /server/

RUN apt-get update && apt-get install -y dumb-init libsasl2-dev python-dev libldap2-dev libssl-dev \
 && pip install pyrad python-ldap \
 && chmod -R 755 /server

EXPOSE \
  1812/tcp 1812/udp \
  1813/tcp 1813/udp

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD /usr/local/bin/python /server/server.py
