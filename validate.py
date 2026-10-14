"""Shared, dependency-free validation for the disposable sandbox host."""
import json
import os
import re
import subprocess
import urllib.error
import urllib.request

IMAGES = ('node:20', 'python:3.12', 'golang:1.22')


def validate(repo, ref, image, minutes):
    match = re.fullmatch(r'https://github\.com/([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9_.-]+?)(?:\.git)?/?', repo)
    if not match or match[2] in ('.', '..'):
        raise ValueError('repo must be an https://github.com/OWNER/REPO URL')
    owner, name = match.groups()
    if not re.fullmatch(r'[0-9a-fA-F]{40}', ref):
        raise ValueError('ref must be a full 40-character SHA')
    if image not in IMAGES or not 1 <= int(minutes) <= 30:
        raise ValueError('image must be allow-listed and minutes must be 1..30')
    return owner + '/' + name


def anonymous_git_check(slug):
    # Anonymous, no credential helper, no prompt, no redirects: only an existing public repo at exactly this name answers.
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': os.devnull, 'HOME': '/tmp'}
    result = subprocess.run(['git', '-c', 'credential.helper=', '-c', 'http.followRedirects=false', 'ls-remote',
                             'https://github.com/' + slug + '.git', 'HEAD'], env=env, capture_output=True, timeout=60)
    if result.returncode != 0:
        raise ValueError('subject must be a public repository with matching identity (no redirects)')
    return {'full_name': slug, 'private': False, 'visibility': 'public', 'checked_by': 'anonymous git ls-remote'}


def public_repo(slug):
    # Deliberately anonymous: gh authentication must never establish subject visibility.
    request = urllib.request.Request('https://api.github.com/repos/' + slug,
                                     headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'public-sandbox-study'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        # Hosted runners share IPs, so the anonymous API limit (60/hour) is often spent (hosted run 4).
        if exc.code in (403, 429):
            return anonymous_git_check(slug)
        raise
    if data.get('private') is not False or data.get('visibility', 'public') != 'public' or data.get('full_name', '').lower() != slug.lower():
        raise ValueError('subject must be a public repository with matching identity (no redirects)')
    return data
