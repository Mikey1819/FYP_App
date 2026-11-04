"""Start the workspace on this laptop only and open it in the browser (used by Start.cmd in the client package).

    python -s launch.py [--no-browser]
    python -s launch.py --check        start, confirm the dashboard answers, stop again (used by the package build)

- The dashboard listens on 127.0.0.1, so other people on the same Wi-Fi cannot open it.
- It picks the first free port from 8501, so a second copy does not fail on a busy port.
- Streamlit runs "headless": it never stops to ask for an e-mail address on first use, which would block a client.
- The browser opens only once the dashboard answers, so the first page is never "cannot connect".
Close the window (or press Ctrl+C) to stop the workspace.
"""
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIRST_PORT, PORTS = 8501, 20


def free_port():
    for port in range(FIRST_PORT, FIRST_PORT + PORTS):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    raise SystemExit(f'No free port between {FIRST_PORT} and {FIRST_PORT + PORTS - 1}. Close other copies of the '
                     'workspace and try again.')


def healthy(url):
    try:
        with urllib.request.urlopen(url + '/_stcore/health', timeout=1) as answer:
            return answer.read().strip() == b'ok'
    except OSError:
        return False


def main(argv):
    port = free_port()
    url = f'http://127.0.0.1:{port}'
    command = [sys.executable, '-s', '-m', 'streamlit', 'run', str(HERE / 'app.py'),
               '--server.address', '127.0.0.1', '--server.port', str(port), '--server.headless', 'true',
               '--browser.gatherUsageStats', 'false', '--server.fileWatcherType', 'none',
               '--global.developmentMode', 'false']
    # The working folder is the app folder, so Streamlit finds .streamlit/config.toml (the theme) there.
    process = subprocess.Popen(command, cwd=HERE)
    try:
        deadline = time.monotonic() + 120
        while not healthy(url):
            if process.poll() is not None:
                return process.returncode or 1
            if time.monotonic() > deadline:
                print('The workspace did not start within two minutes.', flush=True)
                process.terminate()
                return 1
            time.sleep(0.5)
        if '--check' in argv:  # Build check: it started and answered; stop it again and leave nothing running.
            print(f'CHECK OK {url}', flush=True)
            process.terminate()
            process.wait(timeout=30)
            return 0
        print(f'The workspace is open at {url}', flush=True)
        print('Keep this window open while you use it. Close it to stop the workspace.', flush=True)
        if '--no-browser' not in argv:
            webbrowser.open(url)
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
