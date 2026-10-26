"""Fixture-only worker readiness and VM command formatting checks."""
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from hardening.scan_exchange import COLLECTOR, worker_status
from hardening.vm_paths import scan_worker_command
from test_evidence_import import MACHINE_UUID, NOW


def worker_fixture(state='ready', now=NOW):
    return dict(schema_version=1, hostname='FIXTURE-SERVER', machine_uuid=MACHINE_UUID,
        collector_sha256=hashlib.sha256(COLLECTOR.read_bytes()).hexdigest(), state=state,
        reported_at=now.isoformat(), valid_until=(now+timedelta(seconds=150 if state=='busy' else 15)).isoformat(),
        worker_instance_id='a'*32)


class WorkerReadinessTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.folder=Path(folder.name)
        self.path=self.folder / ('worker-'+MACHINE_UUID+'.json')

    def status(self, now=NOW):
        return worker_status(self.folder, 'FIXTURE-SERVER', MACHINE_UUID, now=now)

    def save(self, data):
        self.path.write_text(json.dumps(data), encoding='utf-8')

    def test_not_seen_and_state_reports_do_not_create_files(self):
        self.assertEqual(self.status()['state'], 'not_seen')
        self.assertEqual(list(self.folder.iterdir()), [])
        for state in ('ready','busy','stopped'):
            self.save(worker_fixture(state))
            self.assertEqual(self.status()['state'], state)

    def test_expiry_busy_allowance_and_clock_mismatch(self):
        self.save(worker_fixture())
        self.assertEqual(self.status(NOW+timedelta(seconds=15))['state'], 'stale')
        self.save(worker_fixture('busy'))
        self.assertEqual(self.status(NOW+timedelta(seconds=120))['state'], 'busy')
        self.assertEqual(self.status(NOW+timedelta(seconds=150))['state'], 'stale')
        self.assertEqual(self.status(NOW-timedelta(seconds=6))['state'], 'clock_mismatch')

    def test_wrong_target_hash_and_malformed_reports(self):
        for field,value,expected in (
            ('hostname','OTHER','target_mismatch'), ('machine_uuid','cb095a4c-5a1c-48fe-b199-fda775b130a8','target_mismatch'),
            ('collector_sha256','0'*64,'collector_mismatch'), ('schema_version',True,'invalid'),
            ('state','applied','invalid'), ('worker_instance_id','../escape','invalid'),
            ('reported_at','2026-10-19T02:00:00','invalid'),
            ('valid_until',(NOW+timedelta(seconds=16)).isoformat(),'invalid'), ('command','anything','invalid')):
            data=worker_fixture(); data[field]=value; self.save(data)
            with self.subTest(field=field): self.assertEqual(self.status()['state'],expected)
        for raw in (b'{',b'x'*4097,b'\xff',b'{"a":1,"a":2}'):
            self.path.write_bytes(raw)
            self.assertEqual(self.status()['state'],'invalid')

    def test_command_quotes_paths_and_rejects_invalid_identity_and_paths(self):
        digest='a'*64
        command=scan_worker_command('FIXTURE-SERVER',MACHINE_UUID,digest,r"D:\Mikey's $VM`Workspace",r'Z:\scan queue')
        self.assertIn("'D:\\Mikey''s $VM`Workspace\\Watch-ScanRequests.ps1'",command)
        self.assertIn("'Z:\\scan queue'",command)
        self.assertTrue(command.endswith('-WatchSeconds 900 -MaxRequests 5'))
        for host,uuid,sha,directory,queue in (
            ('bad;command',MACHINE_UUID,digest,r'C:\FYP',r'Z:\queue'),
            ('FIXTURE-SERVER','bad',digest,r'C:\FYP',r'Z:\queue'),
            ('FIXTURE-SERVER',MACHINE_UUID,'bad',r'C:\FYP',r'Z:\queue'),
            ('FIXTURE-SERVER',MACHINE_UUID,digest,'relative',r'Z:\queue'),
            ('FIXTURE-SERVER',MACHINE_UUID,digest,r'C:\FYP','Z:\\queue\ncommand')):
            with self.assertRaises(ValueError): scan_worker_command(host,uuid,sha,directory,queue)

    def test_powershell_report_matches_host_contract(self):
        worker=COLLECTOR.with_name('Watch-ScanRequests.ps1')
        digest=hashlib.sha256(COLLECTOR.read_bytes()).hexdigest()
        script=". '"+str(worker).replace("'","''")+"' -FunctionsOnly\n"
        script+="New-ScanWorkerReport 'FIXTURE-SERVER' '"+MACHINE_UUID+"' '"+digest+"' 'busy' '"+'a'*32+"' ([DateTimeOffset]::Parse('"+NOW.isoformat()+"')) | ConvertTo-Json"
        result=subprocess.run(['powershell','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',script],
                              capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        self.path.write_text(result.stdout,encoding='utf-8')
        self.assertEqual(self.status()['state'],'busy')
