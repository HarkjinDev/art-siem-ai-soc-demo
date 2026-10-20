"""Slack Socket Mode bridge: new events only, idempotent posts, draft-only human review.
No ART execution, Wazuh rule modification or production deployment.
"""
import logging
import re
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

import requests
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('soc-slack')
URL = os.getenv('SOC_API_URL', 'http://soc-demo:8000').rstrip('/')
CHANNEL = os.environ['SLACK_CHANNEL_ID']
BOT_DB = os.getenv('BOT_DB_PATH', '/data/slack.sqlite')
POLL_SECONDS = max(2, int(os.getenv('SLACK_POLL_SECONDS', '10')))
# On initial deployment, avoid spamming historical demo records.
STARTED_AT = datetime.now(timezone.utc)
ALLOWED_USERS = set(filter(None, (v.strip() for v in os.getenv('SLACK_APPROVER_IDS', '').split(','))))
app = App(token=os.environ['SLACK_BOT_TOKEN'], signing_secret=os.environ['SLACK_SIGNING_SECRET'])


def database():
    con = sqlite3.connect(BOT_DB, timeout=20)
    con.execute('PRAGMA busy_timeout=20000')
    con.execute('CREATE TABLE IF NOT EXISTS posts (event_id TEXT PRIMARY KEY, channel TEXT, thread_ts TEXT)')
    con.execute('''CREATE TABLE IF NOT EXISTS draft_actions (
        event_id TEXT PRIMARY KEY, state TEXT NOT NULL, requester TEXT,
        draft_id TEXT, updated_at TEXT NOT NULL
    )''')
    con.execute('''CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL,
        draft_id TEXT, actor TEXT NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL
    )''')
    return con


def now():
    return datetime.now(timezone.utc).isoformat()


def is_new(event):
    try:
        return datetime.fromisoformat(event['ts'].replace('Z', '+00:00')) >= STARTED_AT
    except (ValueError, KeyError, TypeError):
        return False



def _unescape_llm_text(value):
    """Decode common LLM Markdown escapes (including double-escaped text).

    Never unescape arbitrary path backslashes, so Windows command paths survive.
    """
    t = str(value or '').replace('\r\n', '\n').replace('\r', '\n')
    for _ in range(4):
        old = t
        t = t.replace('\\r\\n', '\n').replace('\\n', '\n')
        t = re.sub(r'\\?<br\s*/?>', '\n', t, flags=re.I)
        # Collapse escaped Markdown syntax, including multi-escaped punctuation.
        t = re.sub(r'\\([#*_>|~`\[\]\(\)!+-])', r'\1', t)
        if old == t:
            break
    return t


def _plain_slack(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _split_pipe(line):
    line = line.strip()
    if not (line.startswith('|') and line.endswith('|')):
        return None
    return [c.strip() for c in line[1:-1].split('|')]


def _render_markdown_lines(text):
    """Render Markdown line structure while preserving code blocks."""
    t = _unescape_llm_text(text)
    output = []
    table_header = None
    in_fence = False
    for line in t.split('\n'):
        line = line.strip(' \t')
        if re.match(r'^```', line):
            in_fence = not in_fence
            table_header = None
            output.append(line)
            continue
        if in_fence:
            output.append(line)
            continue
        cells = _split_pipe(line)
        if cells is not None:
            if all(re.fullmatch(r':?-{3,}:?', cell or '') for cell in cells):
                continue
            if table_header is None:
                table_header = cells
                continue
            pairs=[]
            for i, val in enumerate(cells):
                heading=table_header[i] if i<len(table_header) else '항목'
                pairs.append(f'*{heading}*: {val}')
            output.append('• ' + '  |  '.join(pairs))
            continue
        table_header = None
        if re.fullmatch(r'[-*_─]{3,}', line):
            output.append('────────────')
            continue
        head = re.match(r'^#{1,6}\s*(.+)$', line)
        if head:
            output.append('*' + head.group(1) + '*')
            continue
        line = re.sub(r'^[-*+]\s+', '• ', line)
        output.append(line)
    return '\n'.join(output)


def slack_text(text):
    """Convert common Markdown to Slack mrkdwn without truncating content."""
    t = _render_markdown_lines(text)
    # Keep code fences and inline code untouched, except for Slack escaping.
    segments = re.split(r'(```[\s\S]*?```|`[^`\n]*`)', t)
    parts = []
    for segment in segments:
        if segment.startswith('`'):
            parts.append(_plain_slack(segment))
            continue
        segment = _plain_slack(segment)
        segment = re.sub(r'\*\*(.+?)\*\*', r'*\1*', segment)
        segment = re.sub(r'(?<!\w)__(.+?)__(?!\w)', r'*\1*', segment)
        segment = re.sub(r'\[([^\]]+)\]\((https?://[^\s)]+)\)', r'\1 (\2)', segment)
        # AI sometimes emits SQL/YAML fence language without a fence.
        segment = re.sub(r'(?m)^(sql|yaml|json|python)\s*$', r'`\1`', segment, flags=re.I)
        parts.append(segment)
    t = ''.join(parts)
    t = re.sub(r'(?m)(────────────)(?=\S)', r'\1\n', t)
    t = re.sub(r'\n{3,}', '\n\n', t)
    return t.strip()


def _section_chunks(rendered, limit=2750):
    """Lossless chunking at newlines, with fallback for oversized lines."""
    if not rendered:
        return ['(내용 없음)']
    output=[]
    chunk=''
    for line in rendered.splitlines(keepends=True):
        while line:
            room=limit-len(chunk)
            if room<=0:
                output.append(chunk)
                chunk=''
                room=limit
            if len(line)<=room:
                chunk+=line
                line=''
            else:
                # Prefer whole lines, but always make progress on long single lines.
                if chunk:
                    output.append(chunk)
                    chunk=''
                else:
                    output.append(line[:limit])
                    line=line[limit:]
    if chunk:
        output.append(chunk)
    return output


def report_messages(label, report, max_blocks_per_message=20):
    """Return multiple Slack messages; never truncate report content."""
    chunks=_section_chunks(slack_text(report))
    size=max(1,max_blocks_per_message-1)
    messages=[]
    total=(len(chunks)+size-1)//size
    for start in range(0,len(chunks),size):
        n=start//size+1
        title=label if total==1 else f'{label} ({n}/{total})'
        blocks=[{'type':'section','text':{'type':'mrkdwn','text':f'*{title}*'}}]
        blocks.extend({'type':'section','text':{'type':'mrkdwn','text':c}} for c in chunks[start:start+size])
        messages.append((title,blocks))
    return messages


def post_report(client, channel, thread_ts, label, text):
    """Send every part, fail visibly if any Slack API call fails."""
    for title,blocks in report_messages(label,text):
        result=client.chat_postMessage(channel=channel,thread_ts=thread_ts,
                                       text=title+' (본문은 블록에 포함)',blocks=blocks)
        if isinstance(result,dict) and result.get('ok') is False:
            raise RuntimeError(f'Slack rejected {title}: {result.get("error")}')


def source_label(ev):
    return {'synthetic':'합성 데이터 / 실제 탐지 아님','sample':'샘플','wazuh-real':'실제 Wazuh Alert'}.get(ev.get('source'),'출처 미확인')

def report_blocks(label, report, max_blocks=38):
    """Build root-message report blocks; defer oversized reports to a thread."""
    chunks = _section_chunks(slack_text(report))
    # Root contains two header/context blocks, plus a context event ID.
    # Slack supports at most 50 blocks per message.
    if len(chunks) + 1 > max_blocks:
        return [{'type': 'section', 'text': {'type': 'mrkdwn',
                 'text': f'*{label}*\n보고서가 길어 전체 내용을 아래 스레드에 게시합니다.'}}]
    return ([{'type': 'section', 'text': {'type': 'mrkdwn', 'text': f'*{label}*'}}]
            + [{'type': 'section', 'text': {'type': 'mrkdwn', 'text': item}}
               for item in chunks])


def body_blocks(ev):
    heading = f"SOC L1 | {ev['name']}"
    context = (f"*판정:* {ev['verdict']}  |  *ATT&CK:* {ev['technique']}  |  "
               f"*Level:* {ev['level']}  |  *분석:* {ev['mode']}  |  *출처:* {source_label(ev)}")
    blocks = [
        {'type':'header','text':{'type':'plain_text','text':heading[:150]}},
        {'type':'section','text':{'type':'mrkdwn','text':context[:2900]}},
    ]
    if ev.get('source') == 'synthetic':
        blocks.append({'type':'context','elements':[{'type':'mrkdwn',
            'text':'⚠️ 합성 데이터: 실제 엔드포인트 실행·Wazuh Manager 탐지 확인 없음'}]})
    blocks.extend(report_blocks('L1 분석', ev.get('l1',''), max_blocks=38))
    blocks.append({'type':'context','elements':[{'type':'mrkdwn',
        'text':f"`event:{ev['id']}`"[:250]}]})
    return blocks


def publish(ev, conn):
    # Unique event ID ensures each run only sends a successful delivery once.
    if conn.execute('SELECT 1 FROM posts WHERE event_id=?', (ev['id'],)).fetchone():
        return
    if ev['mode'] in ('queued','filtered'):
        return
    if ev['mode'] == 'ai-error':
        log.warning('AI analysis failed; suppressing normal SOC alert event_id=%s', ev['id'])
        # Persist suppression to avoid repeated scans; errors remain in web dashboard.
        conn.execute('INSERT OR IGNORE INTO posts VALUES (?,?,?)', (ev['id'], 'suppressed', ''))
        conn.commit()
        return
    result = app.client.chat_postMessage(channel=CHANNEL, text=f"SOC L1: {ev['name']}", blocks=body_blocks(ev))
    thread_ts = result['ts']
    # Record successful root post before any further operations: a later failure
    # must not duplicate the root alert when polling retries.
    conn.execute('INSERT OR IGNORE INTO posts VALUES (?,?,?)', (ev['id'], CHANNEL, thread_ts))
    conn.commit()
    if len(_section_chunks(slack_text(ev.get('l1', '')))) + 1 > 38:
        post_report(app.client, CHANNEL, thread_ts, 'L1 분석', ev.get('l1', ''))
    if ev['category'] == 'endpoint_security' and ev['mode'] == 'docker-agent':
        post_report(app.client, CHANNEL, thread_ts, 'L2 심층 분석', ev.get('l2', ''))
        app.client.chat_postMessage(channel=CHANNEL, thread_ts=thread_ts,
            text='L3 Sigma 초안 생성 가능 (운영 변경 없음)', blocks=[
                {'type': 'section', 'text': {'type': 'mrkdwn',
                 'text': '*L3 · Sigma 초안 요청* — 검토용 초안만 생성하며 Wazuh에 적용하지 않습니다.'}},
                {'type': 'actions', 'elements': [
                    {'type': 'button', 'style': 'primary', 'action_id': 'create_draft',
                     'value': ev['id'], 'text': {'type': 'plain_text', 'text': 'Sigma 초안 생성'}}]}
            ])
    elif ev['category'] == 'endpoint_security':
        post_report(app.client, CHANNEL, thread_ts, 'L2 안내', ev.get('l2', ''))


def send_events():
    while True:
        try:
            response = requests.get(URL + '/api/events', timeout=15)
            response.raise_for_status()
            events = response.json()
            with database() as conn:
                for ev in reversed(events):
                    if is_new(ev):
                        try:
                            publish(ev, conn)
                        except Exception:
                            log.exception('Slack delivery failed event_id=%s', ev.get('id'))
        except Exception:
            log.exception('Slack polling failed')
        time.sleep(POLL_SECONDS)


def record_action(event_id, actor, action, draft_id=None):
    with database() as conn:
        conn.execute('INSERT INTO audit(event_id,draft_id,actor,action,created_at) VALUES (?,?,?,?,?)',
                     (event_id, draft_id, actor, action, now()))


def can_review(user_id):
    # Empty allow-list means draft creation is allowed but review is disabled.
    return bool(ALLOWED_USERS) and user_id in ALLOWED_USERS


@app.action('create_draft')
def create_draft(ack, body, client):
    ack()
    event_id = body['actions'][0]['value']
    actor = body['user']['id']
    channel = body['channel']['id']
    thread_ts = body['message'].get('thread_ts') or body['message']['ts']
    with database() as conn:
        result = conn.execute('INSERT OR IGNORE INTO draft_actions(event_id,state,requester,updated_at) VALUES (?,?,?,?)',
                              (event_id, 'GENERATING', actor, now()))
        accepted = result.rowcount == 1
    if not accepted:
        client.chat_postMessage(channel=channel, thread_ts=thread_ts,
                                text='이 이벤트에 대한 Sigma 초안 요청은 이미 접수되었습니다. 중복 생성을 차단했습니다.')
        return
    record_action(event_id, actor, 'REQUEST_DRAFT')
    client.chat_postMessage(channel=channel, thread_ts=thread_ts,
                            text='⚙️ L3 Sigma 초안 생성 시작 (운영 배포 없음)')

    def work():
        try:
            r = requests.post(URL + '/api/events/' + event_id + '/sigma-draft', timeout=180)
            r.raise_for_status()
            x = r.json()
            draft_id = x['id']
            sample_state='NOT_RUN'
            if x['status']=='DRAFT_PYSIGMA_VALID':
                try:
                    vr=requests.get(URL+'/api/sigma-drafts/'+draft_id+'/sample-check',params={'event_id':event_id},timeout=25)
                    vr.raise_for_status()
                    sample_state=vr.json().get('status','INCONCLUSIVE')
                except Exception:
                    log.exception('Sigma sample check failed draft_id=%s',draft_id)
                    sample_state='INCONCLUSIVE'
            may_review=x['status']=='DRAFT_PYSIGMA_VALID' and sample_state=='SAMPLE_MATCH'
            with database() as conn:
                conn.execute('UPDATE draft_actions SET state=?, draft_id=?, updated_at=? WHERE event_id=?',
                             ('AWAITING_REVIEW' if may_review else 'NEEDS_VALIDATION', draft_id, now(), event_id))
            record_action(event_id, actor, 'DRAFT_CREATED', draft_id)
            # Approval is for review disposition only; never triggers rule deployment.
            # Structural validity and limited sample comparison are NOT detection execution.
            draft_text=str(x.get('draft',''))
            blocks=[
                {'type':'section','text':{'type':'mrkdwn','text':
                    f"*L3 Sigma 초안* · pySigma 구조: `{x['status']}` · 제한적 샘플 비교: `{sample_state}`\n"
                    f"SOC Draft ID: `{draft_id}`"}},
                {'type':'section','text':{'type':'mrkdwn','text':
                    '```'+draft_text[:2600]+'```'}},
                {'type':'context','elements':[{'type':'mrkdwn','text':
                    '검증 수준: *구조 검사 + 제한된 필드 샘플 비교*. Wazuh Manager 룰 실행·운영 탐지 검증 아님.'}]},
                {'type':'actions','elements':[
                    {'type':'button','action_id':'review_draft','value':event_id+'|APPROVED_FOR_REVIEW',
                     'text':{'type':'plain_text','text':'검토 승인 (배포 아님)'}},
                    {'type':'button','style':'danger','action_id':'reject_draft',
                     'value':event_id+'|REJECTED',
                     'text':{'type':'plain_text','text':'반려'}}]}
            ]
            if not may_review:
                blocks=[b for b in blocks if b.get('type')!='actions']
                blocks.append({'type':'section','text':{'type':'mrkdwn',
                    'text':'⚠️ pySigma 검증 또는 샘플 매칭 미충족 — 승인·반려 버튼을 표시하지 않습니다.\n' +
                           '; '.join(x.get('validation',{}).get('errors',[]))[:900]}})
            try:
                client.chat_postMessage(channel=channel, thread_ts=thread_ts,
                                        text=f"Sigma 초안 {x['status']} / 샘플 {sample_state} ({draft_id})", blocks=blocks)
            except Exception:
                # The draft is already persisted. Do not relabel successful
                # generation as FAILED merely because Slack delivery failed.
                log.exception('L3 Slack result delivery failed event_id=%s draft_id=%s', event_id, draft_id)
                record_action(event_id, actor, 'SLACK_DELIVERY_FAILED', draft_id)
                try:
                    client.chat_postMessage(
                        channel=channel, thread_ts=thread_ts,
                        text=f"Sigma 초안 생성 및 저장 성공: {draft_id} ({x['status']}). "
                             'Slack 버튼 게시 실패로 검토는 보류됩니다. 관리자에게 확인을 요청하세요.'
                    )
                except Exception:
                    log.exception('L3 Slack fallback delivery failed event_id=%s', event_id)
        except Exception:
            log.exception('L3 generation failed event_id=%s', event_id)
            with database() as conn:
                conn.execute('UPDATE draft_actions SET state=?, updated_at=? WHERE event_id=?',
                             ('FAILED', now(), event_id))
            record_action(event_id, actor, 'DRAFT_FAILED')
            client.chat_postMessage(channel=channel, thread_ts=thread_ts,
                                    text='L3 초안 생성 실패. 서버 로그를 확인하세요. 운영 룰은 변경되지 않았습니다.')
    threading.Thread(target=work, daemon=True).start()


@app.action('review_draft')
@app.action('reject_draft')
def review_draft(ack, body, client):
    ack()
    actor = body['user']['id']
    channel = body['channel']['id']
    thread_ts = body['message'].get('thread_ts') or body['message']['ts']
    try:
        event_id, decision = body['actions'][0]['value'].split('|', 1)
    except (ValueError, KeyError):
        return
    if decision not in ('APPROVED_FOR_REVIEW', 'REJECTED'):
        return
    if not can_review(actor):
        client.chat_postMessage(channel=channel, thread_ts=thread_ts,
                                text='승인 권한이 없습니다. SLACK_APPROVER_IDS 설정을 확인하세요.')
        record_action(event_id, actor, 'UNAUTHORIZED_REVIEW_ATTEMPT')
        return
    with database() as conn:
        current = conn.execute('SELECT state,draft_id FROM draft_actions WHERE event_id=?', (event_id,)).fetchone()
        if not current or current[0] != 'AWAITING_REVIEW':
            client.chat_postMessage(channel=channel, thread_ts=thread_ts,
                                    text='이미 검토가 완료됐거나 검토 가능한 초안이 없습니다.')
            return
        change = conn.execute("UPDATE draft_actions SET state=?,updated_at=? WHERE event_id=? AND state='AWAITING_REVIEW'",
                              (decision, now(), event_id))
        if change.rowcount != 1:
            return
        draft_id = current[1]
    record_action(event_id, actor, decision, draft_id)
    client.chat_postMessage(channel=channel, thread_ts=thread_ts,
        text=f"<@{actor}> · Sigma 초안 `{draft_id}` · *{decision}*\n"
             '※ 검토 대상 승인만 기록했습니다. 구조 검사와 제한적 샘플 비교 외의 실제 Wazuh 탐지 검증·운영 배포는 수행하지 않았습니다.')


if __name__ == '__main__':
    with database():
        pass
    log.info('Slack bridge started, skipping events earlier than %s', STARTED_AT.isoformat())
    threading.Thread(target=send_events, daemon=True).start()
    SocketModeHandler(app, os.environ['SLACK_APP_TOKEN']).start()
