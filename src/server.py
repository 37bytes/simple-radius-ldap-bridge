import os

import ldap
from pyrad import dictionary, packet, server
import logging

log_level = os.getenv('LOG_LEVEL', 'INFO')

try:
    logging.basicConfig(filename='/proc/1/fd/1', level=log_level, format='%(asctime)s [%(levelname)-8s] %(message)s')
except PermissionError:
    logging.basicConfig(filename='/proc/self/fd/1', level=log_level, format='%(asctime)s [%(levelname)-8s] %(message)s')

logging.info('Starting server')

assert os.getenv('LDAP_SERVER'), "Environment variable 'LDAP_SERVER' missing!"
assert os.getenv('LDAP_BASE_DN'), "Environment variable 'LDAP_BASE_DN' missing!"
assert os.getenv('RADIUS_SECRET'), "Environment variable 'RADIUS_SECRET' missing!"
assert os.getenv('LDAP_FILTER_DN'), "Environment variable 'LDAP_FILTER_DN' missing!"
assert os.getenv('LDAP_FILTER'), "Environment variable 'LDAP_FILTER' missing!"


class SimpleLdapProxy(server.Server):

    def HandleAuthPacket(self, pkt):
        user_name = pkt['User-Name'][0]

        logging.info('Received auth request for user "%s"', user_name)

        for attr in pkt.keys():
            logging.debug('Attribute %s=%s', attr, pkt[attr])

        try:
            ldap_client = ldap.initialize(os.environ['LDAP_SERVER'])
            ldap_client.bind_s(
                os.environ['LDAP_BASE_DN'].format(user_name=user_name),
                pkt.PwDecrypt(pkt['User-Password'][0]),
            )
            result = ldap_client.search_s(os.environ['LDAP_FILTER_DN'], ldap.SCOPE_SUBTREE, os.environ['LDAP_FILTER'].format(user_name=user_name))
            if len(result) == 0:
              logging.info('User "%s" not found in %s', user_name, os.environ['LDAP_FILTER'])
              reply = self.CreateReplyPacket(pkt, **{'Reply-Message': 'User not found by filter'})
              reply.code = packet.AccessReject
            else:
              logging.info('User "%s" successfully logged in', user_name)
              reply = self.CreateReplyPacket(pkt)
              reply.code = packet.AccessAccept
        except Exception as exc:
            error_message = exc.__class__.__name__
            logging.exception('Unable to authenticate user "%s" in LDAP: %s', user_name, error_message)
            reply = self.CreateReplyPacket(pkt, **{'Reply-Message': error_message})
            reply.code = packet.AccessReject

        self.SendReplyPacket(pkt.fd, reply)

    def HandleAcctPacket(self, pkt):
        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleCoaPacket(self, pkt):
        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleDisconnectPacket(self, pkt):
        reply = self.CreateReplyPacket(pkt)
        reply.code = packet.CoANAK
        self.SendReplyPacket(pkt.fd, reply)


if __name__ == '__main__':
    srv = SimpleLdapProxy(dict=dictionary.Dictionary('dictionary'), coa_enabled=True)
    srv.hosts['0.0.0.0'] = server.RemoteHost('0.0.0.0', os.environ['RADIUS_SECRET'].encode(), '0.0.0.0')
    srv.BindToAddress('0.0.0.0')
    srv.Run()
