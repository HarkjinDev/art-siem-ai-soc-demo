import os,sys,json,uuid,time
from datetime import datetime,timezone
import requests

base='http://127.0.0.1:8000'
url=os.environ['WAZUH_INDEXER_URL'].rstrip('/')
user=os.environ.get('WAZUH_INDEXER_USER','admin')
password=os.environ['WAZUH_INDEXER_PASSWORD']
ca=os.environ['WAZUH_CA_FILE']
run_id='SOC-E2E-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]
index='wazuh-alerts-soc-e2e-'+datetime.now(timezone.utc).strftime('%Y.%m.%d')
docid=run_id.lower()
headers={'Content-Type':'application/json'}
alert={
 '@timestamp': datetime.now(timezone.utc).isoformat(),
 'timestamp': datetime.now(timezone.utc).isoformat(),
 'id':run_id,
 'agent':{'id':'999','name':'soc-e2e-synthetic'},
 'manager':{'name':'wazuh.manager'},
 'rule':{'id':'990001','level':9,'description':'SOC E2E TEST SYNTHETIC Windows process creation (not real Wazuh detection)',
         'groups':['windows','sysmon','process_creation','soc_e2e_test'],
         'mitre':{'id':['T1059.003','T1057'],'tactic':['Execution','Discovery'],'technique':['Windows Command Shell','Process Discovery']}},
 'decoder':{'name':'windows_eventchannel'},
 'data':{'win':{'system':{'channel':'Microsoft-Windows-Sysmon/Operational','eventID':'1','computer':'soc-e2e-synthetic'},
                'eventdata':{'image':'C:\\Windows\\System32\\cmd.exe','commandLine':'cmd.exe /c tasklist',
                             'parentImage':'C:\\Windows\\explorer.exe','user':'LAB\\soc-e2e'}}},
 'full_log':f'{run_id} SYNTHETIC process event cmd.exe /c tasklist. No endpoint execution.',
 'location':'SOC-E2E-SYNTHETIC'
}

def out(level,msg):
 print(f'[{level}] {msg}',flush=True)

def fail(msg):
 out('FAIL',msg); sys.exit(1)

out('INFO','Indexer synthetic document test: no Manager detection / endpoint execution')
try:
 r=requests.put(f'{url}/{index}/_doc/{docid}?refresh=wait_for',auth=(user,password),verify=ca,json=alert,timeout=40)
 if not r.ok: fail(f'Indexer write HTTP {r.status_code}: {r.text[:280]}')
 out('PASS','Indexer write acknowledged')
 r=requests.get(f'{url}/{index}/_doc/{docid}',auth=(user,password),verify=ca,timeout=20)
 if not r.ok:fail(f'Indexer read HTTP {r.status_code}: {r.text[:280]}')
 retrieved=r.json().get('_source')
 if not retrieved or retrieved.get('id')!=run_id:fail('Indexer document verification mismatch')
 out('PASS','Indexer read-back verified')
 external_id=f'wazuh:{index}:{docid}'
 r=requests.post(f'{base}/api/ingest',json={'alert':{'_id':external_id,'_source':retrieved}},timeout=300)
 if not r.ok: fail(f'SOC ingest HTTP {r.status_code}: {r.text[:280]}')
 item=r.json()
 if item.get('mode')!='docker-agent':fail(f'SOC analysis mode={item.get("mode")}; detail={str(item.get("l1",""))[:260]}')
 if not item.get('l1') or not item.get('l2'): fail('L1/L2 result empty')
 out('PASS','SOC -> Docker Agent L1/L2 completed')
 r=requests.get(f'{base}/api/events',timeout=20)
 if not r.ok:fail('SOC event listing unavailable')
 match=next((e for e in r.json() if e.get('id')==external_id),None)
 if match is None:fail('Event not in recent SOC list; check SOC UI')
 out('PASS','SOC event stored and visible')
 print('RESULT_JSON='+json.dumps({'run_id':run_id,'event_id':external_id,'mode':item['mode'],'name':item.get('name'),'index':index},ensure_ascii=False),flush=True)
 out('INFO','Slack: check SOC-AI-Agent channel for '+run_id+' (notification delivery not observable from this test)')
except requests.exceptions.RequestException as e:
 fail(type(e).__name__+': '+str(e)[:350])
