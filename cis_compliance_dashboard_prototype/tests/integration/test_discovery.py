import importlib.util
import unittest
from system.contracts import Endpoint

class DiscoveryTests(unittest.TestCase):
    def test_protocol_evidence_not_port_number(self):
        self.assertIsNotNone(importlib.util.find_spec('system.discovery'))
        from system.discovery import classify_banner, classify_wsman
        self.assertEqual(classify_banner(b'SSH-2.0-OpenSSH_8.9\r\n'),'ssh')
        for bad in [b'SSH-1.5-old\n',b'hello SSH-2.0-x',b'SSH-2.0-bad\x00\n',b'HTTP/1.1 200 OK\r\n']:
            self.assertIsNone(classify_banner(bad))
        self.assertEqual(classify_wsman(401,{'WWW-Authenticate':'Negotiate, NTLM'},b''),'winrm_candidate')
        self.assertIsNone(classify_wsman(302,{'Location':'http://other/wsman'},b''))
        self.assertIsNone(classify_wsman(200,{},b'<html>hello</html>'))

    def test_probe_only_same_endpoint_and_no_credentials(self):
        self.assertIsNotNone(importlib.util.find_spec('system.discovery'))
        from system.discovery import discover_transport
        seen=[]
        def banner(endpoint,deadline):
            seen.append(('banner',endpoint));return b'SSH-2.0-OpenSSH_8.9\n'
        def http(endpoint,deadline):
            raise AssertionError('SSH evidence must stop discovery')
        result=discover_transport(Endpoint('vm.example',55985),banner_probe=banner,wsman_probe=http)
        self.assertEqual(result.transport,'ssh')
        self.assertEqual(seen,[('banner',Endpoint('vm.example',55985))])

    def test_ambiguous_override_and_timeout_are_explicit(self):
        self.assertIsNotNone(importlib.util.find_spec('system.discovery'))
        from system.discovery import discover_transport
        result=discover_transport(Endpoint('vm',22),banner_probe=lambda *a:b'hello',wsman_probe=lambda *a:(200,{},b'hello'))
        self.assertIsNone(result.transport)
        result=discover_transport(Endpoint('vm',22,'winrm'),banner_probe=lambda *a: (_ for _ in ()).throw(AssertionError()))
        self.assertEqual(result.transport,'winrm')
