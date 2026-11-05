import importlib.util
import tempfile
import unittest
from pathlib import Path
from system.contracts import Endpoint, ConnectionRequest
from system.identity import VerifiedIdentity
from system.session import Credentials, CredentialVault
from system.ledger import CoordinationLedger

class RoutingTests(unittest.TestCase):
    def test_ubuntu_verified_registration_disconnect_and_no_cross_protocol_retry(self):
        self.assertIsNotNone(importlib.util.find_spec('system.connection'))
        from system.connection import ConnectionService
        with tempfile.TemporaryDirectory() as folder:
            vault=CredentialVault(); channel=FixtureSsh()
            service=ConnectionService(CoordinationLedger(Path(folder)/'coord.db'),vault,
                ssh_factory=lambda *a:channel,backend_factory=lambda session:('backend',session.identity.platform))
            request=ConnectionRequest(Endpoint('fixture',22,'ssh'),'vm','a'*32,vault.put(Credentials('user','SECRET')))
            result=service.connect(request)
            self.assertEqual(result.state,'connected')
            self.assertEqual(service.backend_for(result.connection_session_id),('backend','ubuntu'))
            self.assertEqual(channel.reads,1)
            service.disconnect(result.connection_session_id)
            self.assertTrue(channel.closed)
            with self.assertRaises(ValueError):service.backend_for(result.connection_session_id)
            with self.assertRaises(ValueError):vault.take(request.credential_ref)

    def test_auth_failure_returns_safe_diagnostic_and_no_backend(self):
        self.assertIsNotNone(importlib.util.find_spec('system.connection'))
        from system.connection import ConnectionService
        with tempfile.TemporaryDirectory() as folder:
            vault=CredentialVault()
            def fail(*a):raise RuntimeError('SECRET')
            service=ConnectionService(CoordinationLedger(Path(folder)/'coord.db'),vault,ssh_factory=fail,
                backend_factory=lambda s: self.fail('No backend before verified identity'))
            result=service.connect(ConnectionRequest(Endpoint('fixture',22,'ssh'),'vm','a'*32,vault.put(Credentials('u','SECRET'))))
            self.assertEqual(result.state,'disconnected');self.assertNotIn('SECRET',repr(result))

    def test_windows_connection_rejects_wrong_os_before_routing(self):
        self.assertIsNotNone(importlib.util.find_spec('system.connection'))
        from system.connection import verify_windows_facts
        facts=dict(hostname='server',machine_uuid='11111111-2222-3333-4444-555555555555',is_admin=True,
                   os_caption='Microsoft Windows Server 2022 Standard',build_number='20348',part_of_domain=False,domain_role=2)
        self.assertEqual(verify_windows_facts(facts).platform,'windows')
        for key,value in [('build_number','19045'),('part_of_domain',True),('domain_role',3),('is_admin',False)]:
            with self.subTest(key=key),self.assertRaises(ValueError):verify_windows_facts(dict(facts,**{key:value}))

    def test_library_value_error_cannot_echo_key_or_sudo_secret(self):
        from system.connection import ConnectionService
        with tempfile.TemporaryDirectory() as folder:
            vault = CredentialVault()
            def fail(*args):
                raise ValueError('private-key-sentinel sudo-secret-sentinel remote-untrusted-text')
            service = ConnectionService(CoordinationLedger(Path(folder) / 'coord.db'), vault, ssh_factory=fail)
            creds = Credentials('u', key_path='private-key-sentinel', sudo_password='sudo-secret-sentinel')
            result = service.connect(ConnectionRequest(Endpoint('fixture',22,'ssh'),'vm','a'*32,vault.put(creds)))
            self.assertEqual(result.state, 'disconnected')
            for sentinel in ('private-key-sentinel', 'sudo-secret-sentinel', 'remote-untrusted-text'):
                self.assertNotIn(sentinel, repr(result))

class FixtureSsh:
    def __init__(self):self.reads=0;self.closed=False
    def verify_identity(self,request):
        self.reads+=1
        return VerifiedIdentity('ubuntu','vm','a'*32,'22.04','ssh','SHA256:'+'a'*43)
    def close(self):self.closed=True
