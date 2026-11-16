"""Versioned current-task wire identity, independent of launch or execution policy."""
import hashlib
import json
import re


def _require_selection(request: dict) -> None:
    selected = request['selection']
    if (not isinstance(selected, dict) or set(selected) != {'kind', 'project_id'} or
            selected['kind'] not in ('explicit', 'project') or
            (selected['kind'] == 'explicit' and selected['project_id'] is not None) or
            (selected['kind'] == 'project' and (not isinstance(selected['project_id'], str) or
                not re.fullmatch('PVT_[A-Za-z0-9_-]+', selected['project_id']))) or
            (request['action'] == 'start' and request['predecessor_sha256'] is not None)):
        raise ValueError('Current request selection is invalid')


def _require_history(history: list) -> None:
    identifiers = []
    for item in history:
        if (not isinstance(item, dict) or set(item) != {'id', 'publisher_id', 'body_sha256'} or
                any(type(item[key]) is not int or item[key] <= 0 for key in ('id', 'publisher_id')) or
                not isinstance(item['body_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', item['body_sha256'])):
            raise ValueError('Current request history is invalid')
        identifiers.append(item['id'])
    if identifiers != sorted(set(identifiers)):
        raise ValueError('Current request history is inconsistent')


def current_request_generation(request: object) -> str:
    """Version 1 remains retry-only; version 2 adds explicitly selected initial work."""
    if not isinstance(request, dict):
        raise ValueError('Current request identity is invalid')
    version = request.get('schema_version')
    fields = {'schema_version', 'id', 'action', 'repository', 'issue_id',
              'requirements_sha256', 'predecessor_sha256', 'history'}
    if version == 2:
        fields.add('selection')
    if (set(request) != fields or type(version) is not int or version not in (1, 2) or
            request['action'] not in (('retry',) if version == 1 else ('start', 'retry'))):
        raise ValueError('Current request identity is invalid')
    if version == 2:
        _require_selection(request)
    if (type(request['issue_id']) is not int or request['issue_id'] <= 0 or
            not isinstance(request['repository'], str) or
            not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', request['repository']) or
            any(not isinstance(request[key], str) or not re.fullmatch('[0-9a-f]{64}', request[key])
                for key in ('id', 'requirements_sha256')) or
            (request['action'] == 'retry' and (not isinstance(request['predecessor_sha256'], str) or
                not re.fullmatch('[0-9a-f]{64}', request['predecessor_sha256']))) or
            not isinstance(request['history'], list) or len(request['history']) > 10000 or
            (version == 1 and not request['history'])):
        raise ValueError('Current request identity fields are invalid')
    _require_history(request['history'])
    checksum = hashlib.sha256(json.dumps({k: v for k, v in request.items() if k != 'id'},
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if request['id'] != checksum:
        raise ValueError('Current request identity changed')
    return 'request-v' + str(version) + '-' + checksum
