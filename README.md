# Hermes Windows Bridge

Hermes가 Windows PC의 MCP 도구를 비공개로 호출하도록 하는 Windows 전용 Bridge입니다. Gateway는 `127.0.0.1:8765/mcp`만 수신하고, Tailscale Serve가 같은 tailnet의 Hermes에만 HTTPS 경로를 제공합니다. Gateway bearer token, Host/Origin 검증, Tailscale App Capability, Named Pipe ACL, 사용자 세션 Worker, typed privileged helper를 함께 사용합니다.

## 프로젝트 상태

Windows 전용 MCP Bridge의 소스와 테스트, 설치 스크립트를 제공합니다. 설치에는 로컬 관리자 권한과 Tailscale 설정이 필요합니다. 개인 환경의 운영 기록과 실행 증거는 저장소에 포함하지 않습니다.

## 보안 불변식

- Gateway backend는 `127.0.0.1`에만 bind합니다. LAN 또는 인터넷 공개 바인딩으로 바꾸지 마십시오.
- Tailscale Serve만 사용합니다. 인터넷 공개 기능은 이 Bridge의 운영 경로가 아닙니다.
- bearer token은 저장소, `config.yaml`, 로그, issue, 채팅, PowerShell history에 기록하지 않습니다.
- `HERMES_BRIDGE_TOKEN`은 Gateway 프로세스의 비밀 환경 변수이고, `HERMES_WINDOWS_BRIDGE_TOKEN`은 Oracle Hermes가 HTTP Authorization header에 보낼 별도 환경 변수 이름입니다. 값은 같은 비밀이지만 파일·환경 범위는 각각 최소 권한으로 분리합니다.
- Privileged Helper는 typed `reboot`·`shutdown` RPC만 보유합니다. 일반 명령 실행이나 상승 shell은 제공하지 않습니다.
- 원격 입력 재활성화 도구는 MCP에 없습니다. 비상 정지는 로컬에서만 해제할 수 있습니다.

## 사전 점검

2026-09-09 Windows-MCP 입력 연결을 운영 Worker에 적용했습니다. Worker의 사용자 데이터 폴더(기본 `%LOCALAPPDATA%\HermesWindowsBridge`)에 `windows-mcp.json`을 만들고 `python_executable`에 별도로 설치한 Windows-MCP 환경의 Python 절대 경로를 지정하면 stdio 자식 프로세스를 사용합니다. 설정 파일이 없으면 기존 입력을 사용하며, 잘못된 설정은 시작 실패로 처리합니다. 공유 Gateway 설정은 변경하지 않습니다. Gateway 인증·승인과 Worker 비상 정지, 활성 창 검사는 기존 경로를 거칩니다. 화면 관찰·UIA·Codex·Job·전원 도구는 기존 구현을 유지합니다. 전용 시험 창에서 이동·클릭·스크롤·단축키·반복 입력과 비상 정지 상태의 입력 거부를 확인했습니다. 운영 적용 뒤 실제 OCI Hermes의 상태 조회·관찰·현재 위치로의 이동도 성공했으며, 도구 실행 기록을 별도로 확인했습니다.

입력 전에 구현을 선택합니다. 클릭·이동·일반 수직 스크롤·단축키·키 입력은 Windows-MCP로 보내고, 현재 커서에 텍스트를 입력하는 기능과 수평/미세 휠 입력은 의미가 달라지지 않도록 기존 Windows 입력을 사용합니다. Windows-MCP 호출 실패 뒤 다른 구현으로 재시도하지 않습니다.

Windows PowerShell에서 프로젝트 루트로 이동해 의존성을 동기화하고, 변경 없는 계획을 확인합니다.

```powershell
uv sync --all-groups
powershell -NoProfile -File .\scripts\install.ps1 -Json
powershell -NoProfile -File .\scripts\doctor.ps1 -Json
```

`install.ps1`은 기본적으로 read-only plan만 출력합니다. 관리자 권한, `uv`, Python 3.14, Tailscale CLI, runtime entrypoint와 기존 transaction 상태를 검토하십시오. 생성될 서비스와 task는 고정되어 있습니다.

Windows GUI Worker에는 [Microsoft Visual C++ v14 x64 Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)가 필요합니다. guest에서 서명된 Microsoft runtime 설치 뒤 MFC DLL load와 Worker import 실패가 1→0으로 전환됐고, Sandbox first-install receipt/readback도 확인했습니다. 개별 DLL 복사나 호스트 자동 설치를 하지 말고, 사용자 계정과 Worker 등록은 변경하지 마십시오.

| 구성 요소 | 계정/범위 | 용도 |
| --- | --- | --- |
| `HermesWindowsBridgeGateway` | `NT AUTHORITY\LocalService` | loopback MCP Gateway |
| `HermesWindowsBridgePrivileged` | `LocalSystem` | typed reboot/shutdown RPC |
| `HermesWindowsBridgeWorker` | 로그인한 사용자, `InteractiveToken`, Limited | GUI, 브라우저, 사용자 shell |

## 보호된 서비스 runtime 전환

`service-host/`의 .NET 호스트를 `scripts/service-host.ps1`로 패키징합니다. 두 SCM 서비스는 보호된 호스트를 실행하고, 호스트가 실행 전 검증을 마친 뒤 Python child를 시작합니다.

새 호스트는 `hosts\<sha256>\<gateway|privileged>`의 실행 파일과 검증기를 사용하며, `host-config.json`에 연결할 release와 manifest 해시를 고정합니다. SCM 등록은 `HermesBridge.ServiceHost.exe --profile gateway|privileged`이고, 검증을 통과한 Python `service_child`만 실행합니다. `RUNNING`은 실제 listener 또는 pipe 준비 후 `READY 1`을 받은 상태입니다. 정지 요청은 `STOP`으로 전달하며, 제한 시간 안에 정지하지 않으면 Job Object의 자식 프로세스를 종료합니다.

새 호스트의 서비스 오류 번호는 검증 실패 `1001`, 검증 시간 초과 `1002`, 잘못된 준비 응답 `1003`, 준비 시간 초과/EOF `1004`, 자식 시작 실패 `1005`, 실행 중 자식 비정상 종료 `1006`, 정지 시간 초과 `1007`입니다. 실행 중 비정상 종료는 SCM 복구 정책이 작동하도록 호스트도 종료합니다.

다음은 새 호스트 패키지와 설치 후보를 확인하는 읽기 전용 명령입니다. 경로와 해시는 실제 빌드 결과의 값으로 대체합니다.

```powershell
powershell -NoProfile -File .\scripts\service-host.ps1 -BuildHost `
  -SourceRoot 'C:\project\hermes_bridge' `
  -ProgramRoot 'C:\Program Files\HermesWindowsBridge' `
  -ReleaseRoot '<verified protected release root>' `
  -ExpectedManifestSha256 '<verified manifest sha256>' -Json
powershell -NoProfile -File .\scripts\install.ps1 `
  -ServiceReleaseRoot '<verified protected release root>' `
  -GatewayServiceHostRoot '<verified gateway host root>' `
  -PrivilegedServiceHostRoot '<verified privileged host root>' -Json
```

이후 운영 업데이트에서도 먼저 기존 pointer·서비스 설정·Worker 등록과 후보 빌드 결과를 보관하고, 위 설치 계획을 확인합니다. 승인된 관리자 실행에서만 같은 설치 명령에 `-Apply`를 추가합니다. 설치기는 두 서비스의 실행 경로와 계정, 호스트·자식 관계 및 doctor 결과를 확인한 뒤 active pointer를 갱신합니다. 실패하면 기존 검증된 release와 호스트 등록을 복구하며, 복구 실패는 수동 조치가 필요한 상태로 남깁니다. 완료 결과와 `doctor.ps1 -Security -ServeHost $serveHost -Json`을 보관해야 하며, 빌드 성공만으로 운영 전환을 완료 처리하지 않습니다. v10 운영 적용 완료와 별개로 격리 SCM의 변조·장애 시험은 계속 미완료 항목입니다.

이 전환의 대상은 Gateway와 Privileged Helper 두 서비스뿐입니다. 로그인 사용자 Worker의 Python·계정·`InteractiveToken`/Limited 등록은 유지됩니다.

- service release는 일반 checkout이나 `.venv`가 아닌 `%ProgramFiles%\HermesWindowsBridge\releases\<64자리 release ID>` 아래에서 별도로 build·검증됩니다. build CLI는 `scripts\service-runtime.ps1 -BuildRelease`이며, `-SourceRoot`, `-ProgramRoot`, trusted `uv` 경로와 source/lock/uv SHA-256 값을 모두 요구합니다. 승인된 build receipt의 정확한 입력을 사용하십시오.
- 설치/업데이트는 `scripts\install.ps1 -ServiceReleaseRoot <검증된 release root>`로 후보를 선택합니다. 실제 `-Apply`는 두 서비스의 exact readback과 doctor 확인 뒤에만 active pointer를 commit하며, 기존 protected release만 자동 복구 후보입니다. 이전 정의가 unsafe/mixed이면 자동 복구 대신 수동 복구 필요 상태가 됩니다.
- `scripts\doctor.ps1 -Security -ServeHost $serveHost -Json`은 active pointer를, `-ServiceReleaseRoot <검증된 release root>`는 pointer commit 전 후보를 read-only로 검사합니다. SCM `PathName`에서 새 후보를 만들지 않으며, raw path/SDDL/예외는 결과에 출력하지 않습니다.
- `scripts\uninstall.ps1 -Apply`는 registration을 제거해도 protected release와 active pointer를 기본 보존합니다. release 삭제나 수동 pointer 편집은 이 절차의 일부가 아닙니다.

아래 명령은 상태/계획 확인용이며, 실제 `-Apply`는 별도 로컬 관리자 승인 후에만 실행하십시오.

설치된 서비스의 인증을 진단할 때 `$serveHost`에는 현재 Windows PC의 Tailscale Serve hostname을 지정하십시오. `-ServeHost`를 생략하면 기본 loopback Host가 인증 검사 전에 403으로 차단되어 `bearer_auth`가 실패할 수 있습니다. 올바른 hostname을 지정한 검사는 토큰 누락·잘못된 토큰 모두 401이어야 합니다. 실제 hostname과 token 값은 진단 결과나 공유 문서에 기록하지 마십시오.

같은 `-ServeHost`는 `transport_policy`의 read-only loopback 경계 검사에도 필요합니다. 이 검사는 인증된 `GET`의 상태 코드만 확인하며 MCP 도구 호출이나 응답 본문 처리를 하지 않습니다.

```powershell
powershell -NoProfile -File .\scripts\doctor.ps1 -Security -ServeHost $serveHost -Json
powershell -NoProfile -File .\scripts\doctor.ps1 `
  -ServiceReleaseRoot '<verified protected release root>' -Json
powershell -NoProfile -File .\scripts\install.ps1 `
  -ServiceReleaseRoot '<verified protected release root>' -Json
```

## 승인 후 Windows 설치

다음 호출은 파일, ACL, token, 서비스, scheduled task를 변경하고 서비스를 시작합니다. 실제 machine mutation 권한을 확인한 뒤에만 관리자 PowerShell에서 실행하십시오.

```powershell
powershell -NoProfile -File .\scripts\install.ps1 `
  -Apply -ConfigureTailscale `
  -ServeHost 'windows-host.<tailnet>.ts.net'
```

선택적으로 브라우저 도구를 위한 Chromium 설치가 필요할 때만 `-InstallPlaywright`를 추가합니다. 정상 Apply의 결과 receipt와 `scripts\doctor.ps1 -Security -ServeHost $serveHost -Json`의 critical check를 보관하십시오. 설치 script는 OCI Hermes 설정이나 tailnet grant를 자동으로 변경하지 않습니다.

설치 상태를 재확인할 때는 다음을 사용합니다.

```powershell
powershell -NoProfile -File .\scripts\doctor.ps1 -Security -ServeHost $serveHost -Json
```

`fail` critical check가 있으면 원격 연결을 진행하지 말고 먼저 원인을 해결하십시오. 대표 원인은 LocalService Gateway 중지, Worker 미로그인, token ACL 오류, loopback listener 부재, Tailscale Serve 충돌입니다.

## Tailscale Serve와 App Capability

먼저 현재 Serve 상태와 생성될 grant 조각을 read-only로 확인합니다.

```powershell
powershell -NoProfile -File .\scripts\configure-tailscale.ps1 `
  -ServeHost 'windows-host.<tailnet>.ts.net' `
  -HermesSource 'tag:hermes' `
  -WindowsDestination 'tag:windows-bridge' `
  -Json
```

스크립트가 반환하는 `recommendedGrantFragment`는 tailnet policy에 **수동으로 병합**합니다. 기존 policy를 덮어쓰지 마십시오. `desiredServeArgv`는 private Serve에 `hermes.local/windows-control` App Capability를 요구하며 backend는 계속 `127.0.0.1:8765`입니다. 설치된 Tailscale이 App Capability forwarding을 지원하지 않거나 기존 Serve 구성이 비어 있지 않고 일치하지 않으면 Apply를 거부합니다.

관리자 승인 후에만 실제 Serve를 적용합니다.

```powershell
powershell -NoProfile -File .\scripts\configure-tailscale.ps1 `
  -Apply -ServeHost 'windows-host.<tailnet>.ts.net' `
  -HermesSource 'tag:hermes' `
  -WindowsDestination 'tag:windows-bridge' -Json
```

Windows 재시작 뒤 Tailscale 연결이 필요하면 조직 정책에 맞춰 Tailscale unattended mode를 별도로 승인·설정하십시오. Serve/App Capability는 bearer token을 대체하지 않습니다. Gateway는 forwarded capability header도 Serve hostname과 loopback peer 조건이 동시에 맞을 때만 인정합니다.

## Oracle Cloud Hermes 연결

OCI에서 현재 구성의 백업을 만들고, 기존 `mcp_servers` mapping 안에 아래 항목을 병합합니다. 실제 hostname과 token 값 대신 placeholder만 사용합니다.

```yaml
mcp_servers:
  windows_pc:
    url: "https://windows-host.<tailnet>.ts.net/mcp"
    headers:
      Authorization: "Bearer ${HERMES_WINDOWS_BRIDGE_TOKEN}"
    timeout: 120
    connect_timeout: 20
    supports_parallel_tool_calls: false
    trust: untrusted
    elicitation:
      enabled: true
      timeout: 300
    tools:
      resources: false
      prompts: false
```

Hermes 비밀 저장소 또는 해당 process의 제한된 환경 파일에 `HERMES_WINDOWS_BRIDGE_TOKEN`을 설정하고, 구성 YAML에는 literal token을 쓰지 마십시오. UNIX 파일을 직접 운영한다면 소유자만 읽을 수 있도록 권한을 제한하십시오. 환경을 갱신한 뒤 운영자가 승인한 Hermes service reload 방식으로 반영하고 Hermes 대화에서 다음 명령을 실행합니다.

```text
/reload-mcp
```

처음에는 `trust: untrusted`를 유지하십시오. Hermes는 `readOnlyHint`가 없는 쓰기 가능 도구를 승인 표면으로 보냅니다. Bridge 자체도 privileged/destructive 흐름에 독립 승인을 요구합니다. Bridge를 직접 통제하고 `status`부터 스모크를 통과한 뒤에만 `trust: full` 전환을 검토하십시오. `supports_parallel_tool_calls: false`는 Worker 입력과 GUI 상태의 직렬성을 보존하는 초기 설정입니다.

## 전원 작업 사용자 확인

2026-09-09 사용자 확정: 전원 작업 승인은 Hermes의 요청별 사용자 확인(MCP form elicitation)만 사용합니다. 별도 Windows 로컬 승인 화면/fallback 구현 요구는 제외합니다. 모델 자동 승인·승인 ID 직접 발급은 허용하지 않으며, 거절·취소·미지원·만료 시 실행을 차단하고 payload 고정/일회성 소비를 유지합니다. 이 결정은 아래 과거 독립 로컬 승인 요구·미해결 기록보다 우선합니다.

Hermes에서 재부팅·종료를 요청하면 작업 내용을 확인하고 이번 요청만 승인하십시오. 거절하거나 응답하지 않으면 실행하지 않습니다. 운영 연결에서 확인 요청 전달과 거절 시 차단을 확인했고, 2026-09-09 사용자의 직접 승인에 따른 실제 재부팅 및 연결 복구도 확인했습니다. 실제 종료는 시험하지 않았습니다.

## Token 회전

1. Oracle Hermes와 Gateway가 새 token을 동시에 사용할 수 있는 유지보수 창을 잡습니다.
2. 먼저 계획을 확인하고, 관리자 로컬 콘솔에서만 별도 Apply를 실행합니다.

```powershell
powershell -NoProfile -File .\scripts\rotate-token.ps1 -Json
powershell -NoProfile -File .\scripts\rotate-token.ps1 -Apply
```

3. Apply의 단 한 번 출력된 새 token을 승인된 비밀 관리 경로로 옮긴 뒤 Oracle Hermes 환경 값을 교체합니다.
4. Hermes를 reload하고 `/reload-mcp` 뒤 `status`를 호출합니다.
5. `doctor.ps1 -Security -ServeHost $serveHost -Json` 결과와 rotation receipt를 보관합니다.

`rotate-token.ps1 -Apply -Json`은 새 token을 JSON에 포함하므로 실행하지 마십시오. token 값은 로그 리다이렉션, clipboard history, source control, `.env.example`에 저장하지 마십시오. 회전 실패 시 script는 이전 token backup 복구를 시도하며, rollback 실패 receipt는 즉시 운영자 검토가 필요합니다.

## 비상 정지와 로컬 재활성화

원격 입력 도구는 persistent marker가 존재하면 `emergency_stop`으로 거부되고 queued input도 취소됩니다. marker가 활성화된 동안 `status`와 관찰 도구는 계속 조회할 수 있지만 click/type/UIA mutation은 실행되지 않습니다.

Worker는 로컬 `Ctrl+Alt+Shift+F11`을 비상 정지 키로 등록합니다. 키 등록 실패 시 Worker transport 시작을 거부하며, 실행 중 키 감지 오류가 나면 입력 차단과 Worker 중지를 요청합니다. 변경 전부터 실행 중인 Worker에는 재시작 후 적용됩니다. 실제 로컬 키 입력 뒤 marker 생성·audit 기록·OCI status의 입력 비활성화, 실제 클릭 요청의 `emergency_stop` 거부와 관리자 reset 뒤 복구를 확인했습니다. 거부 결과의 MCP 오류 분류 보완은 서비스 반영 후 재검증이 필요합니다.

`scripts\enable-remote-input.ps1`은 **이미 로컬에서 활성화된** 비상 정지 marker를 해제하는 관리자 전용 reset helper입니다. 원격 MCP 재활성화 도구는 제공하지 않습니다. 로컬 활성화는 Worker 전용 `user_data/worker-audit`에 원문 키 입력 없이 기록합니다. 이 경로의 24시간 cleanup은 legacy sensitive body에만 적용되며 redacted JSONL 보존 기간은 아닙니다.

로컬 관리자가 상태를 읽고 승인 후 재활성화할 때만 다음을 사용합니다.

```powershell
powershell -NoProfile -File .\scripts\enable-remote-input.ps1 -Json
powershell -NoProfile -File .\scripts\enable-remote-input.ps1 -Apply
```

## 제거

먼저 계획과 backup 대상만 확인합니다.

```powershell
powershell -NoProfile -File .\scripts\uninstall.ps1 -Json
```

승인된 제거는 세 개의 고정 registration만 제거하고 config, token, browser profile, user data를 기본 보존합니다.

```powershell
powershell -NoProfile -File .\scripts\uninstall.ps1 -Apply
```

`-RemoveUserData`는 사용자 browser profile과 data를 삭제하므로 별도 백업 검토 후에만 사용하십시오. Uninstall은 tailnet policy나 다른 Serve handler를 reset하지 않습니다. Bridge handler 정리는 현재 Serve 상태를 검토한 뒤 범위를 좁혀 수동 수행해야 합니다.

## PC 상태별 동작

| PC 상태 | Gateway/status | 사용자 shell/files | GUI·Browser·Codex | Privileged Helper |
| --- | --- | --- | --- | --- |
| 로그인 및 desktop unlock | 가능 | 가능 | 가능 | policy/approval 뒤 가능 |
| 로그인 및 Windows lock | 가능 | 대체로 가능 | 제한 또는 불가 | policy/approval 뒤 가능 |
| 부팅, 사용자 미로그인 | 가능 | Interactive Worker 없음 | 불가 | typed operation만 제한적 가능 |
| sleep 또는 전원 꺼짐 | 불가 | 불가 | 불가 | 불가 |
| UAC secure desktop | Gateway 유지 | 일반 사용자 범위만 | secure desktop 자동화 불가 | typed RPC만 |
| BIOS/UEFI | 불가 | 불가 | 불가 | 불가 |

Windows logon password 입력, UAC secure-desktop bypass, credential extraction, BIOS/UEFI automation, generic SYSTEM shell은 지원하지 않습니다.

## 문제 해결

| 증상 | 확인 순서 | 조치 |
| --- | --- | --- |
| `windows_pc` tool이 없음 | Hermes config, secret environment, `/reload-mcp` | YAML indentation과 `mcp_servers.windows_pc` URL을 확인하고 status부터 재시도 |
| bearer/Origin/Host 거부 | `doctor.ps1 -Security -ServeHost $serveHost -Json` | token, Serve hostname, `HERMES_BRIDGE_ALLOWED_HOSTS`, `HERMES_BRIDGE_ALLOWED_ORIGINS`를 함께 점검 |
| Tailscale Apply conflict | `configure-tailscale.ps1 -Json` | 다른 Serve handler를 덮어쓰지 말고 기존 소유자와 scoped cleanup을 결정 |
| GUI나 Browser가 offline | `status`의 desktop/worker 상태 | 대상 사용자가 로그인·unlock 상태인지, Worker task가 Limited 권한으로 실행 중인지 확인 |
| 입력이 `emergency_stop` | `doctor.ps1 -Security -ServeHost $serveHost -Json` | 로컬 운영자가 marker 원인을 확인한 뒤에만 reset helper 실행 |
| reboot/shutdown 승인 실패 | Hermes 사용자 확인(MCP elicitation) | approval receipt를 새로 요청하고 payload 변경 없이 한 번만 소비 |
| Tailscale 재시작 뒤 연결 안 됨 | Tailscale status와 organization policy | unattended mode 승인·설정과 Serve status를 확인 |

## 개발 검증

```powershell
uv lock --check
uv run pytest -q
uv run ruff check .
uv run basedpyright
```

공식 설정 의미는 [Hermes MCP Config Reference](https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference), private reverse proxy와 App Capability 동작은 [Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve), [Serve examples](https://tailscale.com/docs/reference/examples/serve), [App Capabilities](https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities), 재시작 전후 연결 조건은 [Tailscale unattended mode](https://tailscale.com/docs/how-to/run-unattended)를 기준으로 검토했습니다.
