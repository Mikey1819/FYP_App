import importlib.util
import unittest
from system.contracts import Endpoint, ConnectionRequest
from system.session import Credentials

class SshTests(unittest.TestCase):
    def test_untrusted_key_sends_no_credentials(self):
        self.assertIsNotNone(importlib.util.find_spec('backends.ubuntu.ssh_channel'))
        from backends.ubuntu.ssh_channel import SshChannel
        channel=FakeTransport(); request=ConnectionRequest(Endpoint('fixture',22,'ssh'),'vm','a'*32,'opaque')
        with self.assertRaises(ValueError):SshChannel.connect(request,Credentials('user','SECRET'),transport_factory=lambda *a:channel,socket_factory=lambda *a:FakeSocket())
        self.assertEqual(channel.auth,[]);self.assertTrue(channel.closed)

    def test_selected_password_no_fallback_and_fixed_identity(self):
        self.assertIsNotNone(importlib.util.find_spec('backends.ubuntu.ssh_channel'))
        from backends.ubuntu.ssh_channel import SshChannel, fingerprint
        transport=FakeTransport()
        request=ConnectionRequest(Endpoint('fixture',22,'ssh'),'vm','a'*32,'opaque')
        channel=SshChannel.connect(request,Credentials('user','SECRET',confirmed_fingerprint=fingerprint(FakeKey())),transport_factory=lambda *a:transport,socket_factory=lambda *a:FakeSocket())
        self.assertEqual(transport.auth,[('user','SECRET',False)])
        self.assertEqual(transport.keepalive,15)  # A restarted server shows up as a closed connection.
        channel.close();self.assertTrue(transport.closed)

class FakeSocket:
    def close(self):pass
class FakeKey:
    def asbytes(self):return b'PUBLIC TEST KEY'
class FakeTransport:
    def __init__(self):self.auth=[];self.closed=False
    def start_client(self,timeout):pass
    def get_remote_server_key(self):return FakeKey()
    def auth_password(self,user,password,fallback):self.auth.append((user,password,fallback))
    def is_authenticated(self):return True
    def set_keepalive(self,seconds):self.keepalive=seconds
    def close(self):self.closed=True
