"""Shared, dependency-free validation for the disposable sandbox host."""
import json
import re
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


def public_repo(slug):
    # Deliberately anonymous: gh authentication must never establish subject visibility.
    request = urllib.request.Request('https://api.github.com/repos/' + slug,
                                     headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'public-sandbox-study'})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    if data.get('private') is not False or data.get('visibility', 'public') != 'public' or data.get('full_name', '').lower() != slug.lower():
        raise ValueError('subject must be a public repository with matching identity (no redirects)')
    return data
