#!/usr/bin/env python3
"""Run the diagnostic projection test against a new, disposable local PG cluster."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
PG = Path('/opt/homebrew/opt/postgresql@17/bin')

with tempfile.TemporaryDirectory(prefix='sfactory-diagnostic-projection-') as tmp:
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    pg_env = {'PATH': '/usr/bin:/bin', 'HOME': tmp, 'LC_ALL': 'C'}
    subprocess.run([str(PG / 'initdb'), '-D', tmp + '/pg', '-U', 'sfactory', '-A',
                    'trust', '--no-instructions'], env=pg_env, check=True,
                   stdout=subprocess.DEVNULL)
    with open(tmp + '/postgres.log', 'w') as log:
        postgres = subprocess.Popen([str(PG / 'postgres'), '-D', tmp + '/pg',
                                    '-h', '127.0.0.1', '-p', str(port), '-k', tmp],
                                   env=pg_env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            while subprocess.run([str(PG / 'pg_isready'), '-h', '127.0.0.1', '-p',
                                  str(port)], env=pg_env, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL).returncode:
                if postgres.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('disposable PostgreSQL did not start')
                time.sleep(.1)
            subprocess.run([str(PG / 'createdb'), '-h', '127.0.0.1', '-p', str(port),
                            '-U', 'sfactory', 'sfactory_diagnostic_fixture'],
                           env=pg_env, check=True)
            env = os.environ.copy()
            env['SFACTORY_DIAGNOSTIC_FIXTURE_DATABASE_URL'] = (
                f'postgres://sfactory@127.0.0.1:{port}/sfactory_diagnostic_fixture')
            subprocess.run(['cargo', 'test', '--locked', '--offline', '-p', 'control-plane',
                            '--all-features', '--bin', 'control-plane',
                            'tests::diagnostic_submission_does_not_write_authoritative_qualifier_projection',
                            '--', '--ignored', '--exact', '--nocapture'],
                           cwd=ROOT, env=env, check=True)
        finally:
            if postgres.poll() is None:
                postgres.terminate()
                try:
                    postgres.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    postgres.kill()
                    postgres.wait(timeout=5)
