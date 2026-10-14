# Disposable public repository research sandbox

Status: **partial; no hosted run verified yet**. This directory is a standalone payload
for a NEW, empty public GitHub repository. It observes public third-party code in
a disposable hosted environment.

## Rules and execution boundary

Public third-party code only. Never supply private code, internal URLs, customer data,
keys, credentials, private repositories or commands containing private information.
Do not configure repository/organization secrets or attach private networks to the
sandbox. Each manual run uses a fresh GitHub-hosted Ubuntu VM, discarded afterwards.
Logs and artifacts are public (artifact retention seven days; downloads can persist).
Never run runner.py, studied setup/run commands or Docker studies on our computers/VPS.

The workflow checks out only its own sandbox code with empty GitHub permissions and
no persisted checkout credentials. Anonymous API validation rejects private subjects
and redirected identities. A full SHA is mandatory and verified after fetch.
setup/run are passed as argv values, never
interpolated into a host shell. Choose node:20, python:3.12 or golang:1.22.

Docker gets no host environment, socket, home, credentials or private mounts. Source is
read-only at /source; /work is a writable copy without Git metadata. Bootstrap installs
strace as container root. The root tracer uses `strace -u nobody` to run both phases
as uid 65534 with env -i, only PATH and HOME=/tmp. Root receives SYS_PTRACE to trace
across uid boundaries; the subject loses its capabilities when strace drops uid.
The subject cannot regain them under no-new-privileges. `/trace` is root-owned 0755;
root owns its logs. The subject cannot overwrite the logs or signal the root tracer.
Tracer diagnostics, signals and timeouts are conservatively flagged as "tracer
exited early" (a signalled subject can also cause this flag). Docker enforces
2 GiB memory, 2 CPUs, 256 PIDs and no-new-privileges. Setup/run share a 1..30 minute
budget (default ten); setup failure skips run. Clone/image/bootstrap have separate
180-second command deadlines; the whole job has a 45-minute ceiling. Cleanup removes
the container before reading trace evidence. Cancellation/job timeout may prevent
artifact upload: no artifact is an incomplete study, never a clean result.

Host tcpdump records packets and DNS before clone/image/bootstrap/subject activity.
The pcap is a 10 MB single-file ring (`-C 10 -W 1`), so later traffic replaces older
packets. DNS text is limited to 1 MiB on Ubuntu's `/bin/sh` (2048 512-byte blocks);
its capture exits at the limit. Each phase's trace and diagnostic file is capped at
8 MiB by RLIMIT_FSIZE; the combined strace log is at most 16 MiB. Caps mean lost
evidence, not absence of activity. The report streams decoding/lines and keeps at
most 200 entries per list, with string fields capped at 300 characters and `+N more`
counts (omitted hosts/pairs count observations, not distinct values).
Before the subject starts, DOCKER-USER and INPUT rules drop traffic from docker0
to 169.254.169.254, 168.63.129.16 and the docker0 gateway. INPUT is necessary for
services addressed to the host itself. The rules are included in egress-rules.txt.
The report records destinations with counts, DNS queries, write-capable opens and
mutation attempts outside /work and /tmp (failures marked), fd writes, process events,
and trusted host-side phase exit codes/durations. stdout/stderr from subject phases
are discarded; this is an observation harness, not a complete test-output archive.

## Evidence limits

A clean observation does not certify safety. TLS payloads, encrypted DNS, unexercised
code paths, time bombs and environment-sensitive behavior remain unknown. Mutable
image tags/dependencies can change despite a pinned source SHA (image ID is recorded).
The container shares the hosted kernel, has outbound network access, and is not a
hardened malware detonation VM. Only the listed metadata addresses and gateway are
blocked, not all private-address ranges or alternate host interfaces. It must
never have access to company infrastructure. Host capture includes GitHub, Docker
and package-manager traffic; it does not attribute packets to individual processes.

strace can be detected or overwhelmed by the subject; reaching a log cap truncates
evidence and may terminate tracing. Root ownership protects logs against ordinary
subject uid access, not a kernel/container escape. The root tracer's capability
separation must be verified on each supported image in the first hosted run.
Root-filesystem writes may be denied because phases are unprivileged. A writable open
does not prove bytes were written. Relative cwd/dirfd handling is best effort;
resumed/interleaved syscalls, thread-shared cwd, exotic mutations and dropped capture
packets need raw-log review. Missing logs and parser diagnostics remain visible.
Reports and traces are untrusted public content; never execute anything they suggest.
No artifact is automatically installed into another system.

## Inputs and reading the report

Manual dispatch takes a public `repo` URL, a full 40-character commit `ref`,
`setup` and `run` commands containing public data only, an allow-listed `image`,
`minutes` (default 10, maximum 30), and a unique `request_id` for correlation.
The workflow run title is `study-<request_id>`.

Read `report.md` first and compare `report.json` with the raw trace, DNS and packet
capture artifacts. Check source SHA, image identity, phase status, durations and
missing-evidence warnings before interpreting destinations or write candidates.
Treat all recorded subject text as untrusted data, never instructions. A failed
or incomplete run cannot establish that the subject performed no harmful actions.
