#!/usr/bin/env python3
"""Check Gmail (INBOX + SPAM) for new emails since the last known historyId.

Usage:
  python poll_gmail.py                          # first run — initialise historyId
  python poll_gmail.py --history-id <id>        # subsequent runs — return new messages
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_service():
    from orchestrator import get_gmail_service, _gmail_execute_with_retry
    for session in ['amira', 'default']:
        try:
            svc = get_gmail_service(session)
            _gmail_execute_with_retry(svc.users().getProfile(userId='me'))
            return svc, _gmail_execute_with_retry
        except Exception:
            continue
    raise RuntimeError('No valid Gmail token (token_amira.json / token_default.json)')


def main():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--history-id', default='')
    args = p.parse_args()

    try:
        service, execute = get_service()
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        return

    try:
        if not args.history_id:
            # First run: snapshot current state, nothing to analyse yet
            profile = execute(service.users().getProfile(userId='me'))
            history_id = profile.get('historyId', '')
            print(json.dumps({
                'newMessages': [],
                'historyId':   history_id,
                'initialized': True,
            }))
            return

        # Subsequent runs: Gmail History API — no labelId filter → catches INBOX + SPAM
        try:
            resp = execute(
                service.users().history().list(
                    userId='me',
                    startHistoryId=args.history_id,
                    historyTypes=['messageAdded'],
                )
            )
        except Exception as e:
            # historyId too old → re-initialise
            profile = execute(service.users().getProfile(userId='me'))
            print(json.dumps({
                'newMessages': [],
                'historyId':   profile.get('historyId', args.history_id),
                'error':       f'History expired, reset: {e}',
            }))
            return

        new_messages = []
        seen = set()
        for record in resp.get('history', []):
            for added in record.get('messagesAdded', []):
                msg    = added.get('message', {})
                labels = msg.get('labelIds', [])
                msg_id = msg.get('id', '')

                if not msg_id or msg_id in seen:
                    continue

                # Accept INBOX and SPAM only (ignore Sent, Drafts, etc.)
                if 'INBOX' in labels:
                    folder = 'INBOX'
                elif 'SPAM' in labels:
                    folder = 'SPAM'
                else:
                    continue

                seen.add(msg_id)
                new_messages.append({'id': msg_id, 'folder': folder})

        print(json.dumps({
            'newMessages': new_messages,
            'historyId':   resp.get('historyId', args.history_id),
        }))

    except Exception as e:
        print(json.dumps({'error': str(e)}))


if __name__ == '__main__':
    main()
