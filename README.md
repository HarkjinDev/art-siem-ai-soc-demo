# ART-SIEM-AI SOC Demo — Final v5.1.2.2

Docker Compose 기반 Wazuh + Docker Agent (Gemini) + SOC Web + Slack ChatOps 데모입니다. **연구·학습·데모 용도**이며 SOC 운영시스템이 아닙니다.

## 기능과 검증 범위

- Wazuh Manager/Indexer/Dashboard 4.14.5 단일 노드 (선택적 `wazuh` 프로파일)
- Wazuh Alert 조회, SQLite 중복 제거, 체크포인트 및 AI 대기열 (데모 수준)
- L1/L2 Docker Agent + Gemini 분석; Slack Socket Mode 게시
- L3 Sigma 초안, pySigma 구문 검사, 제한적 단일 샘플 필드 비교, Slack 검토 승인
- 합성 이벤트 표시: **실제 엔드포인트 실행 또는 Wazuh 룰 발동을 의미하지 않음**
- **검증 기록:** 2026-10-20 사용자 환경에서 합성 E2E Indexer 쓰기/읽기, SOC 분석, Slack L1/L2 게시, Sigma `DRAFT_PYSIGMA_VALID` 및 `SAMPLE_MATCH`, `APPROVED_FOR_REVIEW` 확인. Slack에서 일부 Markdown 이스케이프가 보일 수 있습니다.

## 사전 요구 사항

- Windows 10/11 + PowerShell 5.1 이상 또는 유사 Docker 호스트
- Docker Desktop Linux containers, Docker Compose v2, Git/인터넷 (docker-agent Git 컨텍스트 빌드)
- 권장 RAM 16GB 이상, Wazuh Indexer 실행 환경의 `vm.max_map_count=262144`
- Google Gemini API 키 및 Docker Agent 토큰. Slack은 알림을 원할 때만 Bot/App 토큰 및 채널 지정
- Docker Agent 소스는 외부 저장소를 빌드하며 기본값 `main`입니다. **재현성을 위해 검증한 커밋을 `DOCKER_AGENT_GIT_REF`에 고정하세요.**

## 최초 설치 (Windows PowerShell)

```powershell
git clone https://github.com/<YOUR-GITHUB-ACCOUNT>/art-siem-ai-soc-demo.git
cd art-siem-ai-soc-demo
Copy-Item .env.example .env
notepad .env
```

`.env`에 사용자별로 서로 다른 `WAZUH_INDEXER_PASSWORD`, `WAZUH_KIBANA_PASSWORD`, `WAZUH_API_PASSWORD`, `GOOGLE_API_KEY`, `DOCKER_AGENT_TOKEN`을 설정하고 `DOCKER_AGENT_URL=http://docker-agent:8080`으로 지정합니다. Wazuh API 비밀번호는 대소문자·숫자·특수문자를 포함하는 강력한 값으로 설정하세요. Slack Socket Mode 사용 시 `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`, `SLACK_CHANNEL_ID`, `SLACK_APPROVER_IDS`를 추가합니다. 키와 토큰을 GitHub에 커밋하지 마세요.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup-wazuh.ps1
docker compose --profile wazuh --profile ai --profile slack up -d --build
docker compose --profile wazuh --profile ai --profile slack ps -a
```

- SOC Demo: http://localhost:8088
- Wazuh Dashboard: https://localhost:8443 (로컬 인증서 경고 가능)
- Slack 설정을 하지 않았다면 `--profile slack`을 빼세요. AI 설정이 없다면 `--profile ai`를 빼되 L1/L2 분석은 불가합니다.
- **설치 스크립트는 최초 설치용**입니다. 이미 실행 중인 다른 Wazuh 환경에 덮어쓰지 마세요.
- 첫 실행에서 Manager API 또는 Filebeat 인증 실패 시 Wazuh 계정/해시 동기화 및 보안 초기화가 추가로 필요할 수 있습니다. 이 저장소는 초회 부팅을 모든 플랫폼에서 검증하지 않았습니다.

## API와 테스트

```powershell
Invoke-RestMethod http://localhost:8088/api/collector/status
Invoke-RestMethod -Method Post http://localhost:8088/api/collector/poll
Invoke-RestMethod http://localhost:8088/api/collector/queue/status
Invoke-RestMethod -Method Post http://localhost:8088/api/collector/queue/run
powershell -ExecutionPolicy Bypass -File .\scripts\run-e2e-test.ps1
```

E2E 스크립트는 **합성 Wazuh 형식 문서**를 별도 `wazuh-alerts-soc-e2e-*` 인덱스에 기록합니다. 실제 Manager 룰 탐지, Sysmon 이벤트 또는 실제 공격은 생성하지 않습니다. 테스트는 Gemini API 사용량을 소비할 수 있습니다. Slack 새 메시지는 별도로 확인해야 합니다.

자동 수집은 기본적으로 `WAZUH_AUTO_IMPORT=false`입니다. 필요할 때만 `.env`에서 `true`로 변경하고 `soc-demo`를 재생성하세요. 수집 기본값은 120초, 배치 5건, AI 대기열 처리 최대 2건이며 고정 기간 기반 체크포인트는 누락 가능성이 있습니다.

## 아키텍처

```text
[Wazuh Agents (optional)] -> [Wazuh Manager] -> [Wazuh Indexer]
                                                   |
                                     [SOC Demo: Collector + SQLite Queue]
                                                   |
                                        [Docker Agent / Gemini]
                                                   |
                                         [Slack Socket Mode Bot]
                                                   |
                                  [L3 Sigma + pySigma + Review]
```

## 보안·운영 주의

1. 개발/테스트 전용. **SOC API에 일반 접근 제어가 없으므로 포트 8088은 루프백에만 바인딩**합니다. 임의의 공인 IP로 노출하지 마세요.
2. `.env`, 생성 TLS 인증서/개인키, 실제 계정 해시, DB 파일, Slack 원문/개인정보를 커밋하지 마세요. 기본 Wazuh 템플릿의 **사용하지 않는 기본 계정도 공개된 해시를 갖고 있을 수 있으므로 외부 노출 전에 초기화·비활성화**하세요.
3. Wazuh 단일 노드이며 분산/HA, PIT 기반 정확히 한 번 수집, 완전한 Slack 마크다운, Sigma→Wazuh 자동 배포는 지원하지 않습니다.
4. `APPROVED_FOR_REVIEW`는 검토 기록일 뿐 탐지 정책 배포 승인이 아닙니다. pySigma 문법 및 제한적 샘플 일치는 실제 탐지 검증이 아닙니다.
5. 원격 에이전트를 사용하려면 방화벽과 TLS 구성을 검토한 다음 `WAZUH_BIND_IP`를 변경하세요.
6. `docker compose down -v`는 데이터와 사용자 설정을 삭제하므로 주의하세요.

## 레포지토리

- `app/`: SOC API, 수집/큐/웹 UI
- `slack/`: Slack Socket Mode 및 L3 검토
- `agents/`: Docker Agent 정의
- `wazuh/`: 데모용 Wazuh 구성 템플릿 (인증서는 최초 설치 시 로컬 생성)
- `scripts/`: 설치, 헬스체크, 합성 E2E 테스트
- `tests/`: 오프라인 코드 검증
- `docs/`: Wazuh 추가 설명 및 검증 기록

**License:** MIT (프로젝트 자체 코드 대상. Docker Agent, Wazuh, 외부 이미지/모델은 각자의 라이선스를 따릅니다.)
