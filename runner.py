"""Trusted host orchestrator. Only copy this sandbox directory into the public repo."""
import json
import os
from pathlib import Path
import subprocess
import time
from validate import validate, public_repo

TRACE_BYTES = 8 * 1024 * 1024


def tracer_early(code, timed_out, trace, diagnostics):
    # A signalled subject can also cause this result. Conservatively flag incomplete
    # evidence rather than claiming the tracer survived a signal or a file-size cap.
    return timed_out or code < 0 or code >= 128 or not trace.exists() or not 0 < trace.stat().st_size < TRACE_BYTES or (
        diagnostics.exists() and diagnostics.stat().st_size > 0)


def main():
    root = Path.cwd()
    evidence = root / 'evidence'
    evidence.mkdir(exist_ok=True)
    metadata = {'phases': {phase: {'exit_code': None, 'seconds': None, 'status': 'not_started'}
                           for phase in ('setup', 'run')}, 'status': 'infrastructure_failed'}
    container = 'research-subject'
    # No host tokens or Actions variables reach git, Docker clients or subject commands.
    clean = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
             'HOME': '/tmp/sandbox-host', 'GIT_CONFIG_NOSYSTEM': '1',
             'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
    def call(command, **kwargs):
        return subprocess.run(command, env=clean, check=True, timeout=180, **kwargs)
    try:
        repo, ref = os.environ['STUDY_REPO'], os.environ['STUDY_REF']
        image, minutes = os.environ['STUDY_IMAGE'], int(os.environ['STUDY_MINUTES'])
        slug = validate(repo, ref, image, minutes)
        public_repo(slug)
        metadata.update(repo=repo, ref=ref.lower(), image=image, minutes=minutes,
                        request_id=os.environ['STUDY_REQUEST_ID'])
        source = root / 'subject-source'
        call(['git', '-c', 'credential.helper=', 'init', str(source)])
        call(['git', '-C', str(source), '-c', 'credential.helper=', '-c', 'http.followRedirects=false',
              'fetch', '--depth=1', 'https://github.com/' + slug + '.git', ref])
        call(['git', '-C', str(source), '-c', 'core.hooksPath=/dev/null', 'checkout', '--detach', 'FETCH_HEAD'])
        actual = call(['git', '-C', str(source), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
        if actual.lower() != ref.lower():
            raise ValueError('fetched SHA mismatch')
        trace = root / 'subject-trace'
        trace.mkdir()
        call(['sudo', 'chown', 'root:root', str(trace)])
        call(['sudo', 'chmod', '0755', str(trace)])
        call(['docker', 'pull', image])
        metadata['image_id'] = call(['docker', 'image', 'inspect', '--format', '{{.Id}}', image], capture_output=True, text=True).stdout.strip()
        # Public resolvers: the hosted VM's resolver (168.63.129.16) is blocked for the subject below, which made the
        # bootstrap's apt-get hang until its 180-second deadline.
        call(['docker', 'run', '--rm', '-d', '--name', container, '--env-file', '/dev/null',
              '--dns', '1.1.1.1', '--dns', '8.8.8.8',
              '--memory', '2g', '--cpus', '2', '--pids-limit', '256', '--security-opt', 'no-new-privileges',
              # Only the root tracer receives this capability; strace -u drops the
              # subject's uid and capabilities. no-new-privileges prevents regain.
              # No container-wide fsize limit: it also capped apt's package lists (bootstrap exit 100);
              # each traced phase sets its own limit below.
              '--cap-add', 'SYS_PTRACE',
              '--mount', f'type=bind,src={source},dst=/source,readonly',
              '--mount', f'type=bind,src={trace},dst=/trace', image, 'sleep', 'infinity'])
        try:
            call(['docker', 'exec', container, 'env', '-i', 'PATH=' + clean['PATH'], 'sh', '-c',
                  'apt-get update -qq && apt-get install -y -qq strace && mkdir /work && '
                  'cp -a /source/. /work/ && rm -rf /work/.git && chown -R 65534:65534 /work && '
                  'chown root:root /trace && chmod 0755 /trace'], capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            # Bootstrap output comes from public package mirrors before any subject code runs.
            metadata['bootstrap_stderr_tail'] = (exc.stderr or '')[-800:]
            raise
        deadline = time.monotonic() + minutes * 60
        for phase in ('setup', 'run'):
            start = time.monotonic()
            command = os.environ['STUDY_' + phase.upper()]
            try:
                # Command is an argv value, never inserted into a host shell.
                result = subprocess.run(['docker', 'exec', '--user', '0:0', '--workdir', '/work',
                    container, 'env', '-i', 'PATH=' + clean['PATH'] + ':/usr/local/go/bin', 'HOME=/tmp',
                    'sh', '-c', f'umask 022; ulimit -f {TRACE_BYTES // 512}; exec strace -u nobody -f -yy -s 300 '
                    '-e trace=network,file,process,write,pwrite64,writev,ftruncate '
                    '-o "/trace/$1.log" sh -c \'exec sh -c "$1" >/dev/null 2>&1\' '
                    'subject "$2" 2>"/trace/$1-stderr.log"', 'trace-phase', phase, command],
                    env=clean, timeout=max(.01, deadline - start), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                code, timed_out = result.returncode, False
            except subprocess.TimeoutExpired:
                code, timed_out = 124, True
            metadata['phases'][phase] = {'exit_code': code, 'seconds': round(time.monotonic() - start, 3),
                                         'timed_out': timed_out, 'status': 'finished',
                                         'tracer_exited_early': tracer_early(code, timed_out, trace / (phase + '.log'),
                                                                           trace / (phase + '-stderr.log'))}
            if metadata['phases'][phase]['tracer_exited_early']:
                metadata['status'] = 'incomplete_trace'
                break
            if code:
                metadata['status'] = 'subject_failed'
                break
        else:
            metadata['status'] = 'completed'
    except Exception as exc:
        metadata['error'] = str(exc)
    finally:
        try:
            stopped = subprocess.run(['docker', 'rm', '-f', container], env=clean, capture_output=True, timeout=30)
            metadata['container_cleanup_exit_code'] = stopped.returncode
            if stopped.returncode:
                metadata['status'] = 'infrastructure_failed'
        except (OSError, subprocess.SubprocessError) as exc:
            metadata['cleanup_error'] = str(exc)
            metadata['status'] = 'infrastructure_failed'
        # Copy only a regular trace file; never follow an attacker-controlled symlink.
        import stat
        import shutil
        try:
            found = False
            with (evidence / 'strace.log').open('wb') as target:
                for phase in ('setup', 'run'):
                    for suffix in ('.log', '-stderr.log'):
                        trace_file = root / 'subject-trace' / (phase + suffix)
                        if trace_file.exists() and stat.S_ISREG(trace_file.lstat().st_mode):
                            if trace_file.stat().st_size > TRACE_BYTES:
                                raise ValueError('trace exceeds byte cap')
                            if suffix == '.log':
                                with trace_file.open('rb') as source:
                                    shutil.copyfileobj(source, target)
                                found = True
                            else:
                                shutil.copyfile(trace_file, evidence / trace_file.name)
            if not found:
                metadata['trace_error'] = 'trace missing or not a regular file'
        except (OSError, ValueError) as exc:
            metadata['trace_error'] = str(exc)
        if metadata.get('trace_error') or (evidence / 'strace.log').stat().st_size == 0:
            metadata['status'] = 'infrastructure_failed'
        (evidence / 'metadata.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    return 0 if metadata['status'] == 'completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
