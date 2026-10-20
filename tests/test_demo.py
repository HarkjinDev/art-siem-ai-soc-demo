import os,sys,unittest
from pathlib import Path
os.environ['DB_PATH']='/tmp/soc-demo-test.sqlite'
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.main import classify,triage,samples
class TestDemo(unittest.TestCase):
    def test_classification(self):
        arr=samples(); self.assertEqual([classify(x['_source']) for x in arr],['vulnerability','endpoint_security','endpoint_security','endpoint_security'])
    def test_routing(self):
        arr=samples(); self.assertEqual(triage(arr[0]['_source'])['verdict'],'취약점 관리 대상')
        self.assertEqual(triage(arr[2]['_source'])['verdict'],'오탐 후보')
        self.assertEqual(triage(arr[1]['_source'])['technique'],'T1059.003')
if __name__=='__main__':unittest.main()

class TestApi(unittest.TestCase):
    def test_replay_deduplicates(self):
        from fastapi.testclient import TestClient
        from app.main import app
        client=TestClient(app)
        self.assertEqual(client.post('/api/replay').status_code,200)
        self.assertEqual(client.post('/api/replay').status_code,200)
        self.assertEqual(len(client.get('/api/events').json()),4)

    def test_l3_rejects_without_ai(self):
        from fastapi.testclient import TestClient
        from app.main import app
        client=TestClient(app)
        client.post('/api/replay')
        self.assertEqual(client.post('/api/events/demo-1/sigma-draft').status_code,503)
        self.assertEqual(client.post('/api/events/demo-0/sigma-draft').status_code,400)

class TestSSEParser(unittest.TestCase):
    def test_split_chunks(self):
        from app.main import parse_sse_events
        lines=['data: {"type":"agent_choice",','data: "content":"안녕하세요"}', '', 'data: {"type":"stream_stopped"}', '']
        events=list(parse_sse_events(lines))
        self.assertEqual(events[0]['content'],'안녕하세요')
        self.assertEqual(events[1]['type'],'stream_stopped')
    def test_invalid_json_gives_safe_diagnostic(self):
        from app.main import parse_sse_events
        with self.assertRaisesRegex(RuntimeError,'Invalid Docker Agent SSE JSON'):
            list(parse_sse_events(['data: {"foo":"private', '']))

class TestSigmaStructure(unittest.TestCase):
    def test_valid_sigma_draft(self):
        from app.main import validate_sigma
        text='''```yaml
title: Command interpreter test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: "\\\\cmd.exe"
  condition: selection
```'''
        result=validate_sigma(text)
        self.assertEqual(result['yaml'].splitlines()[0],'title: Command interpreter test')
        self.assertIn(result['validator'], ('pysigma','pysigma-unavailable'))
    def test_invalid_sigma_draft(self):
        from app.main import validate_sigma
        self.assertFalse(validate_sigma('title: unstructured')['valid'])
    def test_malformed_yaml(self):
        from app.main import validate_sigma
        self.assertFalse(validate_sigma('title: [unfinished')['valid'])

class TestSigmaExtraction(unittest.TestCase):
    def test_prose_wrapped_yaml(self):
        from app.main import extract_sigma
        text='설명입니다\n```yaml\ntitle: Test\nlogsource: {}\ndetection: {}\n```\n후속 설명'
        self.assertEqual(extract_sigma(text).splitlines()[0], 'title: Test')
    def test_multiple_fences_blocked(self):
        from app.main import validate_sigma
        self.assertFalse(validate_sigma('```yaml\na: 1\n```\n```yaml\nb: 2\n```')['valid'])
    def test_no_pysigma_is_fail_closed(self):
        from app.main import validate_sigma
        r=validate_sigma('title: Demo\nlogsource:\n  product: windows\ndetection:\n  selection:\n    Image: cmd.exe\n  condition: selection')
        self.assertEqual(r['valid'],r['validator']=='pysigma')
