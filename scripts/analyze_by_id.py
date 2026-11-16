#!/usr/bin/env python3
"""Analyze a single Gmail message by ID and return JSON result.

Usage: python analyze_by_id.py --msg-id <gmail_message_id> [--folder INBOX|SPAM]
"""
import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SCORE_KEYS = {'auth': 'score_auth', 'url': 'score_url', 'nlp': 'score_nlp', 'sandbox': 'score_sandbox'}


def normalize_verdict(raw: str) -> str:
    v = str(raw).upper()
    if 'DANGER'  in v: return 'DANGER'
    if 'SUSPECT' in v or 'QUARANT' in v: return 'SUSPICIOUS'
    return 'SAFE'


def get_service():
    from orchestrator import get_gmail_service, _gmail_execute_with_retry
    for session in ['amira', 'default']:
        try:
            svc = get_gmail_service(session)
            _gmail_execute_with_retry(svc.users().getProfile(userId='me'))
            return svc, _gmail_execute_with_retry
        except Exception:
            continue
    raise RuntimeError('No valid Gmail token')


def detect_folder(meta: dict, fallback: str = 'INBOX') -> str:
    """Detect whether a message is in INBOX or SPAM from its labelIds."""
    labels = meta.get('labelIds', [])
    if 'SPAM' in labels:
        return 'SPAM'
    if 'INBOX' in labels:
        return 'INBOX'
    return fallback


def main():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--msg-id', required=True)
    p.add_argument('--folder', default='')   # auto-detected if not provided
    args = p.parse_args()

    try:
        from orchestrator import build_email_context, orchestrate

        service, execute = get_service()

        # Lightweight metadata call — also used for folder detection + timestamp
        meta = execute(
            service.users().messages().get(
                userId='me', id=args.msg_id, format='metadata',
                metadataHeaders=['From', 'Subject'],
            )
        )
        ts_ms = int(meta.get('internalDate', 0))
        timestamp = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat()

        # Detect folder automatically unless caller passed --folder
        folder = args.folder if args.folder else detect_folder(meta)

        ctx = build_email_context(args.msg_id, service, folder)
        if not ctx:
            print(json.dumps({'error': f'Could not read message {args.msg_id}'}))
            return

        ctx.setdefault('email_hash', hashlib.sha256(
            f"{ctx.get('sender','')}{ctx.get('subject','')}{ctx.get('body_text','')[:200]}".encode()
        ).hexdigest())

        result     = asyncio.run(orchestrate(ctx, reports_dir='reports'))
        scoring    = result.get('scoring', {})
        agents_raw = result.get('agents', {})
        verdict    = normalize_verdict(scoring.get('verdict', ''))

        agents = []
        for name, data in agents_raw.items():
            if not isinstance(data, dict):
                continue
            sk = SCORE_KEYS.get(name, '')
            agents.append({
                'name':    name.upper(),
                'score':   data.get(sk),
                'verdict': str(data.get('verdict', '')).replace('⚠️ ', '').strip(),
                'detail':  str(data.get('detail', data.get('hard_rule', '')))[:120],
            })

        print(json.dumps({
            'id':        ctx['email_hash'],
            'msgId':     args.msg_id,
            'from':      ctx.get('sender', 'unknown'),
            'subject':   ctx.get('subject', '(no subject)'),
            'verdict':   verdict,
            'score':     round(float(scoring.get('score_final', 0)), 1),
            'folder':    folder,
            'timestamp': timestamp,
            'action':    scoring.get('action', ''),
            'hard_rule': scoring.get('hard_rule', ''),
            'agents':    agents,
        }))

    except Exception as e:
        print(json.dumps({'error': str(e)}))


if __name__ == '__main__':
    main()
