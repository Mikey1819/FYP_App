"""Build the client package: one folder, and a zip of it, that a client unzips and starts with Start.cmd.
Developer-only; run it with the project venv (its Python and libraries are what gets shipped):

    cis_compliance_dashboard_prototype\\.venv\\Scripts\\python.exe scripts\\packaging\\build_client_package.py
        [--out dist] [--no-zip] [--no-check]

What goes in (FYP-Hardening\\):
  Start.cmd, README-FIRST.txt
  python\\                the Python that runs the venv (3.15), without its tests, docs, headers and Tk
  python\\Lib\\site-packages  exactly the libraries installed in the venv: the tested set (requirements-lock.txt)
  app\\cis_compliance_dashboard_prototype\\  app.py, launch.py, hardening\\, .streamlit\\config.toml, requirements files
  app\\scripts\\vm\\         the collector and the remediation runner (sent to the server over WinRM)
  app\\scripts\\server_access\\  the server access helper (downloadable from the Servers page)
The folders keep the repository's layout, because the code finds those scripts relative to itself.

What never goes in: data\\ (the developer's lab records), tests, docs, the venv itself, evaluation and lab tools.

The check (unless --no-check) starts the packaged dashboard with the package's own Python and an empty, temporary data
folder, waits until it answers, and stops it again (launch.py --check). Nothing is left running.
"""
import argparse
from datetime import date
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / 'cis_compliance_dashboard_prototype'
NAME = 'FYP-Hardening'

APP_FILES = ['app.py', 'launch.py', 'requirements.txt', 'requirements-lock.txt', '.streamlit/config.toml']
SCRIPT_FILES = ['vm/Collect-Server2022Evidence.ps1', 'vm/Invoke-RemediationAction.ps1',
                'server_access/FYP-ServerAccess.ps1', 'server_access/Start-ServerAccess.cmd',
                'server_access/FYP-ServerAccess-README.txt']
# Parts of a Python installation the workspace never uses.
PYTHON_SKIP = {'Doc', 'include', 'libs', 'Scripts', 'tcl', 'Tools'}
LIB_SKIP = {'test', 'idlelib', 'tkinter', 'turtledemo', 'site-packages', 'ensurepip', '__pycache__'}
DLL_SKIP = ('_tkinter', 'tcl', 'tk')
SITE_SKIP = ('pip', 'pip-')  # Not needed to run; clients never install anything.

START_CMD = r'''@echo off
rem Starts the Server Hardening Workspace and opens it in your browser.
rem Keep this window open while you use the workspace; close it to stop.
setlocal
set "HERE=%~dp0"
rem Your records are kept in your own user folder, not inside this download.
set "DATA=%LOCALAPPDATA%\FYP-Hardening\data"
if not exist "%DATA%" mkdir "%DATA%"
set "CIS_DASHBOARD_DB=%DATA%\preview.sqlite3"
rem Use only the Python and the libraries inside this folder.
set "PYTHONNOUSERSITE=1"
set "PYTHONPATH="
set "PYTHONHOME="
"%HERE%python\python.exe" -s "%HERE%app\cis_compliance_dashboard_prototype\launch.py" %*
if errorlevel 1 (
    echo.
    echo The workspace stopped with an error. The message above says why.
    pause
)
'''

README = '''Server Hardening Workspace
==========================

Checks a stand-alone Windows Server 2022 against 32 CIS Benchmark controls, ranks the findings by risk, proposes
fixes from a fixed, pre-approved list, applies only the fixes you approve, and checks the result.

Start
-----
1. Unzip this folder anywhere (for example your Documents). If Windows says the files came from the internet,
   right-click the zip, choose Properties, tick "Unblock", then unzip again.
2. Double-click Start.cmd. The workspace opens in your browser. Keep the black window open while you use it;
   close it to stop.

Connect a server
----------------
Your laptop and the server must be on the same network (for example the same Wi-Fi).
1. In the workspace: Servers > "Server access helper" > Download helper. Copy the zip to the server.
2. On the server, as administrator: unzip, double-click Start-ServerAccess.cmd, click "Start pairing".
   The helper window shows a one-time code.
3. In the workspace: Servers > Add a server > type the code > Find server. Then type the server's built-in
   Administrator password. The server is saved under "My servers".
4. Open "Agentic hardening" and start a round.
5. When you have finished with a server, click "Revert changes" in the helper on that server.
Next time, pick the server under My servers and type the password. If its address changed, use Re-pair.

The AI agents (optional)
------------------------
The agents use a local AI model through Ollama on this laptop (https://ollama.com), model qwen3:8b
("ollama pull qwen3:8b"). Without it, scanning, risk ranking and approved fixes still work; the workspace says the
AI is unavailable.

Good to know
------------
- Nothing changes on a server until you approve it, and every approval is for one exact change.
- Passwords are never saved, logged or sent to the AI model.
- The workspace can only be opened on this laptop (it listens on 127.0.0.1), not by others on the network.
- Your records: %LOCALAPPDATA%\\FYP-Hardening\\data. To remove everything, delete this folder and that one.
'''


def copy_tree(source, target, skip_dir=lambda d: False, skip_file=lambda f: False):
    for folder, dirs, files in os.walk(source):
        dirs[:] = [d for d in dirs if not skip_dir(Path(folder) / d)]
        for name in files:
            path = Path(folder) / name
            if not skip_file(path):
                destination = target / path.relative_to(source)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, destination)


def build(out):
    if sys.prefix == sys.base_prefix:
        raise SystemExit('Run this with the project venv\'s Python: its libraries are what the package ships.')
    package = out / NAME
    if package.exists():
        shutil.rmtree(package)
    python, base = package / 'python', Path(sys.base_prefix)
    print(f'Python {sys.version.split()[0]} from {base}')
    copy_tree(base, python,
              skip_dir=lambda d: (d.parent == base and d.name in PYTHON_SKIP)
                                 or (d.parent == base / 'Lib' and d.name in LIB_SKIP) or d.name == '__pycache__',
              skip_file=lambda f: f.parent == base / 'DLLs' and f.name.lower().startswith(DLL_SKIP))
    site = Path(sysconfig.get_paths()['purelib'])
    print(f'Libraries from {site}')
    copy_tree(site, python / 'Lib' / 'site-packages',
              skip_dir=lambda d: (d.parent == site and d.name.startswith(SITE_SKIP)) or d.name == '__pycache__',
              skip_file=lambda f: f.suffix == '.pyc')
    app = package / 'app' / APP.name
    for name in APP_FILES:
        (app / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(APP / name, app / name)
    for path in sorted((APP / 'hardening').glob('*.py')):
        (app / 'hardening').mkdir(exist_ok=True)
        shutil.copy2(path, app / 'hardening' / path.name)
    for name in SCRIPT_FILES:
        target = package / 'app' / 'scripts' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / 'scripts' / name, target)
    # Windows batch files and Notepad expect CRLF line ends.
    (package / 'Start.cmd').write_bytes(START_CMD.replace('\n', '\r\n').encode('ascii'))
    (package / 'README-FIRST.txt').write_bytes(README.replace('\n', '\r\n').encode('ascii'))
    for forbidden in ('data', 'tests', '.venv', 'docs'):
        if any(p.name == forbidden for p in (package / 'app').rglob('*') if p.is_dir()):
            raise SystemExit(f'Refusing to ship a "{forbidden}" folder.')
    return package


# Renders every page once with the package's own Python and an empty database (Streamlit's test runner).
PAGES_CHECK = r'''
from streamlit.testing.v1 import AppTest
def servers():
    from hardening.databases import servers_database
    from hardening.servers_view import render_servers
    render_servers(servers_database())
def agentic():
    from hardening.databases import imports_database
    from hardening.agentic_view import render_agentic
    render_agentic(imports_database())
def history():
    from hardening.databases import imports_database
    from hardening.history_view import render_history
    render_history(imports_database())
shown = []
for name, app in (('Overview', AppTest.from_file('app.py', default_timeout=120)),
                  ('Servers', AppTest.from_function(servers, default_timeout=120)),
                  ('Agentic hardening', AppTest.from_function(agentic, default_timeout=120)),
                  ('History and configuration drift', AppTest.from_function(history, default_timeout=120))):
    app.run()
    assert not app.exception, (name, [e.value for e in app.exception])
    assert app.title[0].value == name, (name, app.title[0].value)
    shown.append(name)
print('PAGES OK ' + ', '.join(shown))
'''


def check(package):
    """Start the packaged dashboard with its own Python and an empty data folder; it must answer, then stop."""
    with tempfile.TemporaryDirectory() as data:
        env = {k: v for k, v in os.environ.items() if not k.startswith(('PYTHON', 'VIRTUAL_ENV', 'CIS_'))}
        env.update(PYTHONNOUSERSITE='1', CIS_DASHBOARD_DB=str(Path(data) / 'preview.sqlite3'))
        python = package / 'python' / 'python.exe'
        imports = subprocess.run([str(python), '-s', '-c', 'import sys, streamlit, pypsrp, pandas, pyarrow, altair; '
                                  'print(sys.version.split()[0], sys.prefix)'],
                                 capture_output=True, text=True, env=env, timeout=120)
        if imports.returncode or str(package / 'python') not in imports.stdout:
            raise SystemExit('Packaged Python check failed:\n' + imports.stdout + imports.stderr)
        print('Packaged Python:', imports.stdout.strip())
        pages = subprocess.run([str(python), '-s', '-c', PAGES_CHECK], cwd=package / 'app' / APP.name,
                               capture_output=True, text=True, env=env, timeout=300)
        if pages.returncode or 'PAGES OK' not in pages.stdout:
            raise SystemExit('Packaged pages did not render:\n' + pages.stdout[-2000:] + pages.stderr[-2000:])
        print('Packaged pages render:', pages.stdout.split('PAGES OK ')[1].strip())
        # Start.cmd itself, as a client starts it, with a temporary user folder in place of %LOCALAPPDATA%.
        env.pop('CIS_DASHBOARD_DB')
        env['LOCALAPPDATA'] = data
        # ".\": some shells (NoDefaultCurrentDirectoryInExePath) do not run a bare name from the current folder.
        result = subprocess.run(['cmd', '/c', '.\\Start.cmd', '--check'], cwd=package, capture_output=True, text=True,
                                env=env, timeout=240)
        if result.returncode or 'CHECK OK' not in result.stdout:
            raise SystemExit('Start.cmd did not start the dashboard:\n' + result.stdout[-2000:] + result.stderr[-2000:])
        print('Start.cmd started the dashboard and it answered:', result.stdout.split('CHECK OK ')[1].split()[0])
        if not (Path(data) / 'FYP-Hardening' / 'data').is_dir():
            raise SystemExit('Start.cmd did not create the data folder under %LOCALAPPDATA%.')
        print(r'Start.cmd keeps records under %LOCALAPPDATA%\FYP-Hardening\data.')


def make_zip(package):
    archive = package.parent / f'{NAME}-{date.today():%Y%m%d}.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in sorted(package.rglob('*')):
            if path.is_file():
                bundle.write(path, Path(NAME) / path.relative_to(package))
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', type=Path, default=ROOT / 'dist')
    parser.add_argument('--no-zip', action='store_true')
    parser.add_argument('--no-check', action='store_true')
    args = parser.parse_args()
    package = build(args.out.resolve())
    size = sum(p.stat().st_size for p in package.rglob('*') if p.is_file())
    print(f'Built {package} ({size / 1e6:.0f} MB)')
    if not args.no_check:
        check(package)
    if not args.no_zip:
        archive = make_zip(package)
        print(f'Zipped {archive} ({archive.stat().st_size / 1e6:.0f} MB)')


if __name__ == '__main__':
    main()
