import json, os, sqlite3, threading, uuid, re, logging, time, hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import quote
import requests
import yaml
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

BASE=Path(__file__).resolve().parent.parent
DB=Path(os.getenv('DB_PATH','/data/demo.sqlite'))
SAMPLES=Path(os.getenv('SAMPLES_PATH',str(BASE/'samples'/'events.json')))
AI_URL=os.getenv('DOCKER_AGENT_URL','').rstrip('/')
AI_TOKEN=os.getenv('DOCKER_AGENT_TOKEN','')
SLACK_WEBHOOK=os.getenv('SLACK_WEBHOOK_URL','')
INDEXER_URL=os.getenv('WAZUH_INDEXER_URL','').rstrip('/')
INDEXER_USER=os.getenv('WAZUH_INDEXER_USER','admin')
INDEXER_PASSWORD=os.getenv('WAZUH_INDEXER_PASSWORD','')
INDEXER_CA=os.getenv('WAZUH_CA_FILE','')
AUTO_ENABLED=os.getenv('WAZUH_AUTO_IMPORT','false').lower() in ('true','1','yes')
AUTO_INTERVAL=max(60,int(os.getenv('WAZUH_POLL_SECONDS','120')))
AUTO_BATCH=min(20,max(1,int(os.getenv('WAZUH_POLL_BATCH','5'))))
AUTO_LOOKBACK=min(1440,max(1,int(os.getenv('WAZUH_INITIAL_LOOKBACK_MINUTES','15'))))
AUTO_AI_LIMIT=min(10,max(0,int(os.getenv('WAZUH_AI_PER_POLL','2'))))
CONTEXT_MAX=min(6000,max(300,int(os.getenv('SOC_CONTEXT_MAX_CHARS','2400'))))
stop_poll=threading.Event()
poll_state={'running':False,'last_poll':None,'last_result':None,'last_error':None}

def security_priority(source):
    rule=source.get('rule',{}) or {}
    groups={str(g).lower() for g in (rule.get('groups') or [])}
    if groups.intersection({'sca','syscheck','rootcheck','ossec','inventory','vulnerability-detector','vulnerability'}):
        return False,'baseline'
    if any('sca' in g or 'vulnerability' in g for g in groups):
        return False,'baseline'
    if str(rule.get('description','')).lower().startswith(('cis benchmark','wazuh server started','sca summary')):
        return False,'baseline'
    mitre=(rule.get('mitre') or {}).get('id') or []
    if mitre: return True,'mitre'
    if int(rule.get('level') or 0)>=7: return True,'level'
    return False,'low-priority'

def bounded_context(c, previous=None):
    result=dict(c)
    if previous:
        result['l1_summary']=str(previous)[:CONTEXT_MAX]
    # Prevent raw arbitrary telemetry from overflowing prompts
    for k,v in list(result.items()):
        if isinstance(v,str): result[k]=v[:CONTEXT_MAX]
    return result

@asynccontextmanager
async def lifespan(application):
    stop_poll.clear()
    # On container restart, put interrupted in-flight jobs back in the queue.
    with lock:
        conn=db()
        try:
            conn.execute("UPDATE ai_queue SET state='retry',next_retry=NULL,updated_at=? WHERE state='running'", (datetime.now(timezone.utc).isoformat(),))
            conn.commit()
        finally:
            conn.close()
    worker=None
    if AUTO_ENABLED:
        worker=threading.Thread(target=poll_loop,daemon=True,name='wazuh-alert-poller')
        worker.start()
    try:
        yield
    finally:
        stop_poll.set()
        if worker: worker.join(timeout=5)

app=FastAPI(title='ART-SIEM-AI SOC Demo',version='5.1',lifespan=lifespan)
logger=logging.getLogger('uvicorn.error')
lock=threading.Lock()

def db():
    DB.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(str(DB),timeout=15)
    c.execute('CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, ts TEXT, category TEXT, verdict TEXT, level INTEGER, name TEXT, technique TEXT, l1 TEXT, l2 TEXT, mode TEXT, raw TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS sigma_drafts (id TEXT PRIMARY KEY, event_id TEXT NOT NULL, created_at TEXT NOT NULL, author TEXT NOT NULL, status TEXT NOT NULL, draft TEXT NOT NULL, FOREIGN KEY(event_id) REFERENCES events(id))')
    c.execute('CREATE TABLE IF NOT EXISTS collector_checkpoint (name TEXT PRIMARY KEY, start_ts TEXT NOT NULL, end_ts TEXT NOT NULL, page_offset INTEGER NOT NULL DEFAULT 0)')
    c.execute('CREATE TABLE IF NOT EXISTS ai_queue (event_id TEXT PRIMARY KEY, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_retry TEXT, last_error TEXT, updated_at TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS sigma_reviews (draft_id TEXT PRIMARY KEY, reviewer TEXT NOT NULL, decision TEXT NOT NULL, sample_status TEXT NOT NULL, created_at TEXT NOT NULL)')
    return c

def classify(source):
    groups=source.get('rule',{}).get('groups',[]) or []
    data=source.get('data',{})
    if 'vulnerability-detector' in groups or 'vulnerability' in data: return 'vulnerability'
    if 'win' in data: return 'endpoint_security'
    return 'other'

def triage(source):
    category=classify(source); rule=source.get('rule',{}); mitre=rule.get('mitre',{}) or {}
    mids=mitre.get('id',[]) or []
    if isinstance(mids,str): mids=[mids]
    desc=rule.get('description','')
    ed=source.get('data',{}).get('win',{}).get('eventdata',{})
    cmd=ed.get('commandLine','') or ed.get('targetObject','')
    fp=any(s in json.dumps(source,ensure_ascii=False) for s in ['__PSScriptPolicyTest_','\\CLR_v4.0\\UsageLogs\\','MsMpEng.exe'])
    if category=='vulnerability': verdict='취약점 관리 대상'
    elif fp: verdict='오탐 후보'
    elif mids: verdict='분석 대상 (탐지 존재)'
    elif category=='endpoint_security': verdict='추가 분석 필요'
    else: verdict='기타'
    return dict(category=category,verdict=verdict,level=int(rule.get('level',0)),name=desc,technique=','.join(mids) or '-',command=cmd,agent=source.get('agent',{}).get('name','unknown'))

def deterministic(c):
    if c['category']=='vulnerability':
        return ('Wazuh 취약점 탐지 이벤트입니다. 실제 공격이 아니라 설치 버전의 취약성 보고입니다. 패치 상태를 확인하세요.','취약점 상세정보(CVE, 버전, 수정 버전)를 검토하고 자산담당자에게 전달하세요.')
    if c['verdict']=='오탐 후보':
        return ('정상 행위와 관련될 수 있는 문자열이 발견되어 오탐 후보로 분류했습니다. 자동 확정하지 않습니다.','프로세스 실행 경로 및 서명, 실행 주체를 확인하세요.')
    return (f"{c['agent']}의 이벤트를 확인했습니다. 관련 ATT&CK 표기는 {c['technique']}이며, 이 표기만으로 공격 성공 또는 탐지공백을 단정할 수 없습니다.",
            '원본 Sysmon 이벤트와 프로세스 계보, ART 실행 ID 및 Wazuh 탐지 결과를 상관분석해야 합니다. 이 데모는 Sigma를 자동 배포하지 않습니다.')

def parse_sse_events(lines):
    """Parse complete SSE frames; a frame can contain multiple data: lines."""
    data_lines=[]
    for line in lines:
        if isinstance(line, bytes):
            line=line.decode('utf-8', errors='replace')
        if line == '':
            if data_lines:
                payload='\n'.join(data_lines)
                data_lines=[]
                if payload.strip() == '[DONE]':
                    continue
                try:
                    yield json.loads(payload)
                except json.JSONDecodeError as exc:
                    # Do not log event bodies; they can contain sensitive telemetry.
                    raise RuntimeError(f'Invalid Docker Agent SSE JSON (length={len(payload)}, position={exc.pos}, error={exc.msg})') from exc
            continue
        if line.startswith(':'):
            continue
        if line.startswith('data:'):
            data_lines.append(line[5:].lstrip(' '))
    if data_lines:
        payload='\n'.join(data_lines)
        try:
            yield json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f'Incomplete Docker Agent SSE JSON (length={len(payload)}, position={exc.pos})') from exc


def agent_call(agent,c,role):
    if not AI_URL: raise RuntimeError('Docker Agent API가 설정되지 않음')
    headers={'Content-Type':'application/json', 'Accept':'text/event-stream'}
    if AI_TOKEN: headers['Authorization']='Bearer '+AI_TOKEN
    s=requests.Session(); s.headers.update(headers)
    sid=s.post(AI_URL+'/api/sessions',json={'title':f'SOC-{role}-{uuid.uuid4().hex[:8]}'},timeout=15)
    sid.raise_for_status(); sess=sid.json()['id']
    if agent == 'l3':
        prompt=('다음 로그에서 관찰된 필드만 사용하여 Sigma Rule YAML 문서 하나만 작성하세요. '
                '문서 앞뒤의 설명, Markdown 코드펜스, 임의 가설, 실행/배포 주장은 절대 넣지 마세요. '
                'title, id(UUID), status, description, logsource, detection, falsepositives, level, tags를 포함하세요. '
                'logsource는 windows/process_creation, selection과 condition은 유효하게 작성하세요. '
                '기본 오탐 가능성을 falsepositives에 기재하세요.\n'+json.dumps(c,ensure_ascii=False))
    else:
        prompt='출처별 구분(synthetic=합성/실제 탐지 아님, sample=샘플, wazuh-real=실제 Wazuh 경보)을 명확히 하고 확인된 데이터/가설/추가 확인 필요를 구분하여 한국어로 분석하세요. 단정과 운영 룰 변경 금지.\n'+json.dumps(c,ensure_ascii=False)
    url=f'{AI_URL}/api/sessions/{quote(sess,safe="")}/agent/soc-agent/{agent}'
    with s.post(url,json={'messages':[{'role':'user','content':prompt}]},stream=True,timeout=(10,120)) as resp:
        resp.raise_for_status()
        resp.encoding='utf-8'
        parts=[]; stopped=False; events_seen=0
        for event in parse_sse_events(resp.iter_lines(decode_unicode=True)):
            events_seen+=1
            typ=event.get('type')
            if typ=='agent_choice':
                parts.append(str(event.get('content') or ''))
            elif typ=='error':
                raise RuntimeError('Docker Agent runtime error: '+str(event.get('message',event.get('error','unknown')))[:300])
            elif typ=='tool_call_confirmation':
                raise RuntimeError('도구 승인 대기: 자동승인 금지')
            elif typ=='stream_stopped':
                stopped=True
                if event.get('finish_reason') in ('length','refusal') or event.get('reason')=='max_iterations':
                    raise RuntimeError('AI response incomplete: '+str(event.get('finish_reason') or event.get('reason')))
        if not stopped:
            raise RuntimeError(f'AI stream not completed (events={events_seen})')
    result=''.join(parts).strip()
    if not result: raise RuntimeError('AI returned empty response')
    return result

def extract_sigma(text):
    """Take a single fenced YAML section from prose; never mistake narrative for YAML."""
    t = text.strip()
    fences = re.findall(r'```(?:yaml|yml)\s*\n(.*?)```', t, flags=re.I | re.S)
    if len(fences) == 1:
        return fences[0].strip()
    if len(fences) > 1:
        raise ValueError('여러 개의 YAML 코드블록은 허용되지 않습니다')
    generic = re.findall(r'```\s*\n(.*?)```', t, flags=re.S)
    if len(generic) == 1:
        return generic[0].strip()
    if len(generic) > 1:
        raise ValueError('여러 코드블록은 허용되지 않습니다')
    return t


def validate_sigma(text):
    """Validate YAML and Sigma syntax with pySigma; NOT a Wazuh backend test."""
    try:
        cleaned = extract_sigma(text)
    except ValueError as exc:
        return {'valid':False,'errors':[str(exc)],'yaml':text[:30000], 'validator':'extraction'}
    if not cleaned or len(cleaned)>30000:
        return {'valid':False,'errors':['빈 문서 또는 크기 제한 초과'],'yaml':cleaned[:30000],'validator':'extraction'}
    try:
        docs=list(yaml.safe_load_all(cleaned))
    except yaml.YAMLError as exc:
        return {'valid':False,'errors':['YAML 파싱 실패: '+str(exc)[:180]],'yaml':cleaned,'validator':'yaml'}
    if len(docs)!=1 or not isinstance(docs[0],dict):
        return {'valid':False,'errors':['정확히 하나의 Sigma YAML 맵 필요'],'yaml':cleaned,'validator':'yaml'}
    rule=docs[0]; errors=[]
    for k in ('title','logsource','detection'):
        if k not in rule: errors.append(f'{k} 필수')
    det=rule.get('detection')
    if not isinstance(det,dict) or not det.get('condition'):errors.append('detection.condition 필요')
    if errors:
        return {'valid':False,'errors':errors,'yaml':cleaned,'validator':'structure'}
    try:
        from sigma.rule import SigmaRule
    except ImportError:
        return {'valid':False,'errors':['pySigma 미설치: 검증 성공으로 처리하지 않음'],'yaml':cleaned,'validator':'pysigma-unavailable'}
    try:
        parsed=SigmaRule.from_yaml(cleaned)
        if parsed is None: raise ValueError('empty Sigma rule')
    except Exception as exc:
        return {'valid':False,'errors':['pySigma 검증 실패: '+str(exc)[:300]],'yaml':cleaned,'validator':'pysigma'}
    return {'valid':True,'errors':[],'yaml':cleaned,'validator':'pysigma',
            'note':'pySigma 파싱/문법 검증 통과. Wazuh 변환, 실제 로그 매칭 및 탐지 검증은 수행하지 않음.'}

def notify(record):
    if not SLACK_WEBHOOK: return
    # Incoming webhook은 알림 전용. 상호작용 승인 버튼은 미구현.
    message=f"*SOC DEMO* [{record['category']}] {record['name']}\nL1: {record['l1'][:500]}"
    try: requests.post(SLACK_WEBHOOK,json={'text':message},timeout=8).raise_for_status()
    except requests.RequestException: pass

def source_type(event_id, raw):
    """Origin is inferred from deterministic demo IDs or original Wazuh marker."""
    if event_id.startswith('demo-') or event_id.startswith('ai-test-'):
        return 'sample'
    try:
        doc = json.loads(raw)
        if isinstance(doc, dict) and doc.get('_demo_source') is True:
            return 'sample'
    except (TypeError, ValueError):
        pass
    if event_id.startswith('wazuh:wazuh-alerts-soc-e2e-') or event_id.startswith('soc-e2e-'): return 'synthetic'
    if isinstance(doc if 'doc' in locals() else None,dict) and (doc.get('_synthetic') or doc.get('_e2e_test') or 'synthetic' in str(doc.get('agent',{}).get('name','')).lower()): return 'synthetic'
    return 'wazuh-real' if raw else 'unknown'


def retry_failed(event_id):
    """Retry the original event only; never overwrite already successful results."""
    with lock:
        conn = db()
        try:
            row = conn.execute('SELECT raw,mode FROM events WHERE id=?', (event_id,)).fetchone()
            if row is None:
                raise HTTPException(404,'이벤트 없음')
            raw, mode = row
            if mode != 'ai-error':
                raise HTTPException(409,'ai-error 이벤트만 재분석할 수 있습니다')
            if not AI_URL:
                raise HTTPException(503,'Docker Agent 연결 설정이 없습니다')
            source = json.loads(raw)
            if not isinstance(source,dict) or not isinstance(source.get('rule'),dict):
                raise HTTPException(422,'원본 Wazuh 이벤트 구조가 유효하지 않습니다')
        finally:
            conn.close()
    context=triage(source)
    try:
        context['source_provenance']=source_type(event_id,raw)
        l1=agent_call('l1',context,'L1')
        l2=(agent_call('l2',bounded_context(context,l1),'L2')
            if context['category']=='endpoint_security' and context['verdict']!='오탐 후보'
            else 'L2 심층 분석 대상이 아닌 이벤트입니다. L1 분석을 참조하세요.')
    except Exception as exc:
        logger.warning('AI retry failed event=%s kind=%s',event_id,type(exc).__name__)
        raise HTTPException(502, 'AI 재분석 실패: '+type(exc).__name__+' (원본 및 실패 이력 유지)') from exc
    with lock:
        conn=db()
        try:
            result=conn.execute('UPDATE events SET l1=?,l2=?,mode=? WHERE id=? AND mode=?',
                      (l1,l2,'docker-agent',event_id,'ai-error'))
            conn.commit()
            if result.rowcount != 1:
                raise HTTPException(409,'이미 다른 요청에서 재분석되었습니다')
        finally:
            conn.close()
    return {'id':event_id,'mode':'docker-agent','message':'재분석 완료. SOC DB 갱신 (기존 Slack 게시물은 수정되지 않음)'}


@app.post('/api/events/{event_id}/retry')
def retry_event(event_id:str):
    return retry_failed(event_id)


def process(source, external_id=None, ai_allowed=True):
    if not isinstance(source,dict) or 'rule' not in source: raise HTTPException(400,'Wazuh _source 형식이 아닙니다')
    c=triage(source); c['source_provenance']=source_type(external_id or '',json.dumps(source,ensure_ascii=False)); l1,l2=deterministic(c); mode='rule-demo'
    if AI_URL and ai_allowed:
        try:
            l1=agent_call('l1',c,'L1'); l2=agent_call('l2',bounded_context(c,l1),'L2') if c['category']=='endpoint_security' and c['verdict']!='오탐 후보' else l2
            mode='docker-agent'
        except Exception as e:
            mode='ai-error'; l1='AI 호출 실패 (규칙 기반 분석 대체 금지): '+str(e)[:300]; l2='AI 분석 미완료'
    if not ai_allowed:
        mode='filtered'; l1='자동수집 선별 정책에 따라 AI 호출을 생략했습니다. 원본 Alert는 보존됩니다.'; l2='분석 대상 아님'
    id_=external_id or uuid.uuid4().hex
    record=dict(id=id_,ts=datetime.now(timezone.utc).isoformat(),**{k:c[k] for k in ['category','verdict','level','name','technique']},l1=l1,l2=l2,mode=mode)
    with lock:
        conn=db()
        try:
            cursor=conn.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)',(*[record[k] for k in ['id','ts','category','verdict','level','name','technique','l1','l2','mode']],json.dumps(source,ensure_ascii=False)))
            inserted=cursor.rowcount > 0
            conn.commit()
        finally: conn.close()
    if inserted and mode not in ('filtered','ai-error'): notify(record)
    return record

@app.get('/health')
def health(): return {'status':'ok','ai_mode':bool(AI_URL),'wazuh_configured':bool(INDEXER_URL),'auto_import':AUTO_ENABLED}

@app.get('/api/events')
def events():
    c=db()
    try:
        rows=c.execute('SELECT id,ts,category,verdict,level,name,technique,l1,l2,mode,raw FROM events ORDER BY ts DESC LIMIT 100').fetchall()
        cols=['id','ts','category','verdict','level','name','technique','l1','l2','mode','raw']
        result=[]
        for row in rows:
            item=dict(zip(cols,row))
            item['source']=source_type(item['id'],item['raw'])
            item['evidence']=evidence_summary(item['raw'],item['source'])
            del item['raw']
            result.append(item)
        return result
    finally:c.close()

@app.get('/api/samples')
def samples():return json.loads(SAMPLES.read_text(encoding='utf-8'))

@app.post('/api/replay')
def replay():
    data=samples(); results=[]
    for index,item in enumerate(data):results.append(process(item['_source'],f'demo-{index}'))
    return {'count':len(results),'results':results}

class Ingest(BaseModel):
    alert:dict

@app.post('/api/ingest')
def ingest(request:Ingest):
    item=request.alert
    return process(item.get('_source',item),item.get('_id'))

@app.post('/api/import-wazuh')
def import_wazuh():
    """Read-only import; return JSON for all expected failures, never leak credentials."""
    if not INDEXER_URL or not INDEXER_PASSWORD or not INDEXER_CA:
        raise HTTPException(400, 'Wazuh Indexer URL/계정/CA가 필요합니다')
    q={'size':10,'sort':[{'timestamp':{'order':'desc','unmapped_type':'date'}}],
       'query':{'bool':{'filter':[{'range':{'rule.level':{'gte':3}}}]}}}
    try:
        response=requests.post(INDEXER_URL+'/wazuh-alerts-*/_search',
                               auth=(INDEXER_USER,INDEXER_PASSWORD),verify=INDEXER_CA,
                               json=q,timeout=20)
        if response.status_code == 404:
            # First boot may have no daily alerts index yet.
            return {'count':0,'imported':0,'skipped':0,'errors':[],
                    'message':'wazuh-alerts-* 인덱스가 없습니다. 먼저 Wazuh Alert가 생성되는지 확인하세요.'}
        if not response.ok:
            logger.warning('Wazuh query rejected: HTTP %s',response.status_code)
            raise HTTPException(502,f'Wazuh Indexer 조회 실패: HTTP {response.status_code} (인증/권한/인덱스 상태 확인)')
        try:
            payload=response.json()
            hits=payload['hits']['hits']
        except (ValueError,TypeError,KeyError) as exc:
            logger.warning('Unexpected Wazuh search response: %s',type(exc).__name__)
            raise HTTPException(502,'Wazuh Indexer 검색 응답의 JSON 구조가 올바르지 않습니다') from exc
        if not isinstance(hits,list):
            raise HTTPException(502,'Wazuh Indexer 응답의 hits.hits가 배열이 아닙니다')
        imported=0; skipped=0; errors=[]
        for index,item in enumerate(hits):
            try:
                source=item['_source']
                external_id=item.get('_id') or None
                if not isinstance(source,dict):
                    raise ValueError('_source가 객체가 아닙니다')
                if not isinstance(source.get('rule'),dict):
                    raise ValueError('rule 필드 누락 또는 형식 오류')
                if external_id:
                    with lock:
                        conn=db()
                        try:
                            exists=conn.execute('SELECT 1 FROM events WHERE id=?',(external_id,)).fetchone()
                        finally:conn.close()
                    if exists:
                        skipped+=1
                        continue
                process(source,external_id)
                imported+=1
            except Exception as exc:
                # One malformed alert must not abort processing other alerts.
                logger.exception('Wazuh import event %s failed',index)
                errors.append({'index':index,'reason':f'{type(exc).__name__}: {str(exc)[:220]}'})
        return {'count':imported,'imported':imported,'skipped':skipped,'received':len(hits),
                'errors':errors,'message':f'{imported}건 신규 가져옴, {skipped}건 중복, {len(errors)}건 오류'}
    except HTTPException:
        raise
    except requests.exceptions.SSLError:
        logger.exception('Wazuh Indexer CA/TLS verification failed')
        raise HTTPException(502,'Wazuh TLS 인증서 검증 실패: CA 파일 경로와 인증서를 확인하세요')
    except requests.exceptions.RequestException as exc:
        logger.warning('Wazuh request failed: %s',type(exc).__name__)
        raise HTTPException(502,f'Wazuh Indexer 요청 실패: {type(exc).__name__} (SOC 서버 로그 확인)')
    except Exception as exc:
        logger.exception('Unexpected Wazuh import error')
        raise HTTPException(500,f'Wazuh 가져오기 내부 오류: {type(exc).__name__} (SOC 서버 로그 확인)')

def poll_once():
    """Bounded, persistent fixed-window pagination. New security alerts are queued, never analyzed in poll."""
    if not (INDEXER_URL and INDEXER_PASSWORD and INDEXER_CA):
        raise RuntimeError('Wazuh Indexer 연결 설정 미완료')
    with lock:
        conn=db()
        try:
            row=conn.execute("SELECT start_ts,end_ts,page_offset FROM collector_checkpoint WHERE name='wazuh'").fetchone()
            if row is None:
                end=datetime.now(timezone.utc).isoformat()
                start=(datetime.now(timezone.utc)-timedelta(minutes=AUTO_LOOKBACK)).isoformat()
                conn.execute('INSERT INTO collector_checkpoint VALUES (?,?,?,0)',('wazuh',start,end))
                conn.commit();row=(start,end,0)
        finally:conn.close()
    start,end,offset=row
    query={'from':offset,'size':AUTO_BATCH,'sort':[{'timestamp':{'order':'asc','unmapped_type':'date'}}],
           'query':{'bool':{'filter':[{'range':{'timestamp':{'gte':start,'lte':end}}},
                                      {'range':{'rule.level':{'gte':3}}}]}}}
    r=requests.post(INDEXER_URL+'/wazuh-alerts-*/_search',auth=(INDEXER_USER,INDEXER_PASSWORD),
                    verify=INDEXER_CA,json=query,timeout=20)
    if r.status_code==404:
        hits=[]
    else:
        r.raise_for_status();hits=r.json()['hits']['hits']
    result={'received':len(hits),'new':0,'filtered':0,'ai':0,'queued':0,'duplicates':0,'errors':0}
    for hit in hits:
        try:
            source=hit['_source'];eid='wazuh:'+str(hit.get('_index',''))+':'+str(hit.get('_id',''))
            with lock:
                conn=db()
                try:seen=conn.execute('SELECT 1 FROM events WHERE id=?',(eid,)).fetchone()
                finally:conn.close()
            if seen:
                result['duplicates']+=1;continue
            should_ai,_=security_priority(source)
            if should_ai and AI_URL:
                record=process(source,eid,ai_allowed=False)
                with lock:
                    conn=db()
                    try:
                        conn.execute("UPDATE events SET mode='queued',l1='AI 분석 대기열에 등록됨',l2='분석 대기' WHERE id=?",(eid,))
                        conn.execute("INSERT OR IGNORE INTO ai_queue VALUES (?,'pending',0,NULL,NULL,?)",(eid,datetime.now(timezone.utc).isoformat()))
                        conn.commit()
                    finally:conn.close()
                result['queued']+=1
            else:
                process(source,eid,ai_allowed=False);result['filtered']+=1
            result['new']+=1
        except Exception:
            result['errors']+=1;logger.exception('Auto import failed for one hit')
    # Advance checkpoint only after every hit has been safely processed; failures retry same page.
    if result['errors']==0:
        with lock:
            conn=db()
            try:
                if len(hits)<AUTO_BATCH:
                    new_end=datetime.now(timezone.utc).isoformat()
                    conn.execute("UPDATE collector_checkpoint SET start_ts=?,end_ts=?,page_offset=0 WHERE name='wazuh'",(end,new_end))
                else:
                    conn.execute("UPDATE collector_checkpoint SET page_offset=? WHERE name='wazuh'",(offset+len(hits),))
                conn.commit()
            finally:conn.close()
    return result


def queue_once(limit=None):
    """Single worker; retry transient failures up to three times, preserving source."""
    limit=AUTO_AI_LIMIT if limit is None else min(10,max(0,int(limit)))
    done={'selected':0,'success':0,'failed':0}
    for _ in range(limit):
        with lock:
            conn=db()
            try:
                row=conn.execute("SELECT q.event_id,e.raw FROM ai_queue q JOIN events e ON e.id=q.event_id WHERE q.state IN ('pending','retry') AND (q.next_retry IS NULL OR q.next_retry<=?) ORDER BY q.updated_at LIMIT 1",(datetime.now(timezone.utc).isoformat(),)).fetchone()
                if row: conn.execute("UPDATE ai_queue SET state='running',updated_at=? WHERE event_id=?",(datetime.now(timezone.utc).isoformat(),row[0]));conn.commit()
            finally:conn.close()
        if not row:break
        eid,raw=row;done['selected']+=1
        try:
            source=json.loads(raw);c=triage(source);c['source_provenance']=source_type(eid,raw)
            l1=agent_call('l1',c,'L1')
            l2=agent_call('l2',bounded_context(c,l1),'L2') if c['category']=='endpoint_security' and c['verdict']!='오탐 후보' else 'L2 분석 대상 아님'
            with lock:
                conn=db()
                try:
                    conn.execute("UPDATE events SET l1=?,l2=?,mode='docker-agent' WHERE id=?",(l1,l2,eid))
                    conn.execute("UPDATE ai_queue SET state='done',last_error=NULL,updated_at=? WHERE event_id=?",(datetime.now(timezone.utc).isoformat(),eid))
                    conn.commit()
                finally:conn.close()
            done['success']+=1
        except Exception as exc:
            with lock:
                conn=db()
                try:
                    attempts=conn.execute('SELECT attempts FROM ai_queue WHERE event_id=?',(eid,)).fetchone()[0]+1
                    state='retry' if attempts<3 else 'failed'
                    next_retry=(datetime.now(timezone.utc)+timedelta(minutes=min(10,2**attempts))).isoformat()
                    conn.execute('UPDATE ai_queue SET state=?,attempts=?,next_retry=?,last_error=?,updated_at=? WHERE event_id=?',(state,attempts,next_retry,type(exc).__name__,datetime.now(timezone.utc).isoformat(),eid))
                    if state=='failed':conn.execute("UPDATE events SET mode='ai-error',l1=?,l2='AI 분석 미완료' WHERE id=?",('대기열 AI 분석 실패: '+type(exc).__name__,eid))
                    conn.commit()
                finally:conn.close()
            done['failed']+=1
            logger.warning('AI queue event failed id=%s error=%s',eid,type(exc).__name__)
    return done

def poll_loop():
    # Delay first poll until dependencies have had time to initialize.
    if stop_poll.wait(15):return
    while not stop_poll.is_set():
        poll_state['running']=True
        try:
            result=poll_once()
            result['queue_run']=queue_once()
            poll_state.update(last_poll=datetime.now(timezone.utc).isoformat(),last_result=result,last_error=None)
        except Exception as exc:
            poll_state.update(last_poll=datetime.now(timezone.utc).isoformat(),last_error=type(exc).__name__)
            logger.exception('Wazuh automatic polling failed')
        finally:poll_state['running']=False
        stop_poll.wait(AUTO_INTERVAL)

@app.get('/api/collector/status')
def collector_status():
    return {'enabled':AUTO_ENABLED,'interval_seconds':AUTO_INTERVAL,'batch':AUTO_BATCH,
            'ai_per_poll':AUTO_AI_LIMIT,'lookback_minutes':AUTO_LOOKBACK,**poll_state}

@app.post('/api/collector/poll')
def collector_manual_poll():
    # Explicitly triggered by the local operator; bounded and read-only to Wazuh.
    try:return poll_once()
    except requests.RequestException as exc:
        logger.warning('Manual collector poll failed: %s',type(exc).__name__)
        raise HTTPException(502,'Indexer 연결 오류: '+type(exc).__name__) from exc

@app.post('/api/collector/queue/run')
def queue_manual_run():
    return queue_once()

@app.get('/api/collector/queue/status')
def queue_status():
    conn=db()
    try:
        states=conn.execute('SELECT state,COUNT(*) FROM ai_queue GROUP BY state').fetchall()
        cp=conn.execute("SELECT start_ts,end_ts,page_offset FROM collector_checkpoint WHERE name='wazuh'").fetchone()
        return {'queue':dict(states),'checkpoint':dict(zip(['start_ts','end_ts','page_offset'],cp)) if cp else None}
    finally:conn.close()

def evidence_summary(raw,origin):
    try:
        x=json.loads(raw);rule=x.get('rule',{}) or {};data=x.get('data',{}) or {}
        facts=[{'field':'rule.description','value':str(rule.get('description',''))[:250]},
               {'field':'rule.level','value':str(rule.get('level',''))[:30]},
               {'field':'agent.name','value':str(x.get('agent',{}).get('name',''))[:150]}]
        win=data.get('win',{}).get('eventdata',{})
        for key in ('image','commandLine','parentImage','user'):
            if key in win:facts.append({'field':'data.win.eventdata.'+key,'value':str(win[key])[:350]})
        return {'origin':origin,'facts':[f for f in facts if f['value']],
                'hypotheses':['명령 실행 목적 및 악성 여부는 추가 증거 필요'] if win else [],
                'follow_up':['부모 프로세스·실행 계정·연관 이벤트 교차 확인'] if win else ['원본 Wazuh 로그 및 설정 근거 확인'],
                'note':'원본 필드 기반 메타데이터이며 LLM 구조화 사실검증은 수행하지 않음'}
    except Exception:return {'origin':origin,'facts':[],'hypotheses':[],'follow_up':['원본 이벤트 확인']}

@app.get('/api/sigma-drafts/{draft_id}/sample-check')
def sigma_sample_check(draft_id:str,event_id:str):
    """Diagnostic offline field comparison, NOT pySigma execution or Wazuh rule validation."""
    conn=db()
    try:
        draft=conn.execute('SELECT draft FROM sigma_drafts WHERE id=?',(draft_id,)).fetchone()
        row=conn.execute('SELECT raw FROM events WHERE id=?',(event_id,)).fetchone()
    finally:conn.close()
    if not draft or not row:raise HTTPException(404,'초안 또는 이벤트 없음')
    validation=validate_sigma(draft[0])
    if not validation['valid']:raise HTTPException(422,'유효한 Sigma 초안만 샘플 확인할 수 있습니다')
    rule=yaml.safe_load(validation['yaml'])
    selectors={k:v for k,v in rule['detection'].items() if k!='condition'}
    condition=str(rule['detection'].get('condition','')).strip()
    if condition not in selectors or not isinstance(selectors[condition],dict):
        return {'status':'UNSUPPORTED','reason':'단일 selection 조건만 확인 가능','wazuh_validation':False}
    source=json.loads(row[0]); ed=source.get('data',{}).get('win',{}).get('eventdata',{})
    checks=[]
    for field,expected in selectors[condition].items():
        chunks=field.split('|');name=chunks[0]
        actual=next((v for k,v in ed.items() if k.casefold()==name.casefold()),None)
        if actual is None:
            checks.append({'field':field,'result':'MISSING'});continue
        modifier=chunks[1:]; values=expected if isinstance(expected,list) else [expected]
        if not all(isinstance(v,str) for v in values):
            checks.append({'field':field,'result':'UNSUPPORTED'});continue
        actual=str(actual).casefold()
        if modifier==['contains']:
            ok=any(v.casefold() in actual for v in values)
        elif modifier==['endswith']:
            ok=any(actual.endswith(v.casefold()) for v in values)
        elif modifier==[]:
            ok=any(actual==v.casefold() for v in values)
        else:
            checks.append({'field':field,'result':'UNSUPPORTED'});continue
        checks.append({'field':field,'result':'MATCH' if ok else 'NO_MATCH'})
    if not checks or any(c['result'] in ('MISSING','UNSUPPORTED') for c in checks):state='INCONCLUSIVE'
    else:state='SAMPLE_MATCH' if all(c['result']=='MATCH' for c in checks) else 'SAMPLE_NO_MATCH'
    return {'status':state,'checks':checks,'wazuh_validation':False,
            'note':'간이 단일 selection 비교입니다. Sigma modifiers/조건 전체 실행, pySigma 백엔드 변환, Wazuh 실탐 검증 아님.'}

class SigmaReview(BaseModel):
    reviewer:str
    decision:str
    sample_event_id:str

@app.post('/api/sigma-drafts/{draft_id}/review')
def review_sigma(draft_id:str,request:SigmaReview):
    if request.decision not in ('APPROVED_FOR_REVIEW','REJECTED'):
        raise HTTPException(422,'지원되지 않는 결정')
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{2,80}',request.reviewer):
        raise HTTPException(422,'검토자 형식 오류')
    # This local HTTP API requires an operator token; not public unauthenticated approval.
    # Token is independent of the Slack channel approval list.
    from fastapi import Request
    raise HTTPException(403,'웹 직접 승인 비활성화: Slack 승인자 목록을 통한 검토만 허용')

@app.get('/api/status')
def status():
    services={'demo':'ok','agent':'disabled' if not AI_URL else 'configured-not-verified', 'wazuh':'configured' if INDEXER_URL else 'disabled', 'auto_import':'enabled' if AUTO_ENABLED else 'disabled','slack':'webhook-configured' if SLACK_WEBHOOK else 'disabled'}
    if AI_URL:
        try:
            r=requests.get(AI_URL+'/health', timeout=3)
            services['agent']='reachable' if r.ok else f'http-{r.status_code}'
        except requests.RequestException:
            services['agent']='unreachable'
    return services

@app.post('/api/events/{event_id}/sigma-draft')
def sigma_draft(event_id: str):
    # Draft-only. Approval or Wazuh mutation is not exposed to an LLM.
    conn=db()
    try:
        row=conn.execute('SELECT category,name,technique,raw,l1,l2 FROM events WHERE id=?',(event_id,)).fetchone()
    finally: conn.close()
    if not row: raise HTTPException(404,'이벤트 없음')
    category,name,technique,raw,l1,l2=row
    if category!='endpoint_security': raise HTTPException(400,'엔드포인트 이벤트에 대해서만 생성 가능합니다')
    if not AI_URL: raise HTTPException(503,'Docker Agent 모드를 먼저 활성화하세요')
    data=json.loads(raw); ed=data.get('data',{}).get('win',{}).get('eventdata',{})
    context={'event_name':name,'attack_id':technique,'event_fields':ed,'l1':l1,'l2':l2,'task':'관찰된 필드만 활용해 Sigma 초안을 YAML 형태로 제안. 근거 없는 사실 금지. 배포 및 검증 성공 주장 금지.'}
    try:
        result=agent_call('l3',context,'L3')
    except Exception as e: raise HTTPException(502,'Docker Agent 호출 실패: '+str(e)[:250])
    if len(result)>30000: raise HTTPException(502,'초안 길이 제한 초과')
    check=validate_sigma(result)
    draft_id=uuid.uuid4().hex
    conn=db()
    try:
        conn.execute('INSERT INTO sigma_drafts VALUES (?,?,?,?,?,?)',(draft_id,event_id,datetime.now(timezone.utc).isoformat(),'docker-agent-l3','DRAFT_PYSIGMA_VALID' if check['valid'] else 'DRAFT_INVALID',check['yaml']))
        conn.commit()
    finally:conn.close()
    return {'id':draft_id,'event_id':event_id,'status':'DRAFT_PYSIGMA_VALID' if check['valid'] else 'DRAFT_INVALID','draft':check['yaml'],'validation':check}

@app.get('/api/sigma-drafts')
def list_sigma_drafts():
    conn=db()
    try:
        rows=conn.execute('SELECT id,event_id,created_at,author,status,draft FROM sigma_drafts ORDER BY created_at DESC LIMIT 100').fetchall()
        return [dict(zip(['id','event_id','created_at','author','status','draft'],r)) for r in rows]
    finally:conn.close()

@app.get('/api/sigma-drafts/{draft_id}/validate')
def validate_stored_draft(draft_id:str):
    conn=db()
    try: row=conn.execute('SELECT draft FROM sigma_drafts WHERE id=?',(draft_id,)).fetchone()
    finally:conn.close()
    if not row:raise HTTPException(404,'초안 없음')
    return validate_sigma(row[0])

@app.get('/',response_class=HTMLResponse)
def home():
    return (Path(__file__).resolve().parent/'index.html').read_text(encoding='utf-8')
