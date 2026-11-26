# CoreaVPN for Mac and iPhone

## 개인 기기에 설치

Mac 및 iPhone에서 서버를 측정하려면 저장소 루트의 `CoreaVPN.xcodeproj`를 열고 `CoreaVPN` 스킴을 선택합니다. Xcode의 **Signing & Capabilities → Team**에서 Personal VPN 권한을 사용할 수 있는 개발자 팀을 지정합니다. 설치 대상에서 Mac이나 페어링한 iPhone을 선택하고 실행합니다. 번들 ID를 변경해야 한다면 자신의 팀이 등록할 고유한 값을 사용합니다. [Apple 개발 기기 배포 안내](https://developer.apple.com/documentation/xcode/distributing-your-app-to-registered-devices)

Xcode 26에서 iPhone을 처음 페어링할 때는 데이터 전송용 케이블로 연결하고 iPhone에서 **이 컴퓨터를 신뢰**를 선택합니다. 그 뒤에는 같은 네트워크에서 Wi-Fi로 실행할 수 있습니다. Xcode 27과 iOS 27 이상에서는 두 기기를 같은 Wi-Fi에 연결한 다음 **Device Hub → + → Pair Nearby Device**에서 처음부터 무선으로 페어링할 수 있습니다. 시뮬레이터에서는 앱 화면과 편집 기능을 확인할 수 있습니다. 회선 성능은 실제 iPhone에서 측정합니다. [Apple 기기 페어링 안내](https://developer.apple.com/documentation/xcode/managing-your-simulated-and-physical-devices-in-device-hub)

앱의 **설정**에서 계정과 암호를 Keychain에 저장하고 **VPN 구성 최초 승인**을 누릅니다. 현재 회선에 이름을 붙이고 계정이 사용할 수 있는 그룹을 선택합니다. iPhone 전용 인증 설정이 필요한 서버는 공급자가 해당 계정으로 발급한 IKEv2 구성 파일을 가져옵니다. 서명된 CMS 파일이나 지원하지 않는 인증 조건은 가져오기 화면에 이유가 표시됩니다. [CoreaVPN 서버표](https://coreavpn.net/docs/servers.htm)

개발자 서명 없이 Mac에서 화면과 기록을 확인할 수 있습니다. 기존 Puma 검사 도구를 설정한 Mac에서는 미리보기 앱에서 실제 Puma 연결과 측정도 시작할 수 있습니다. 저장소 루트에서 아래 명령을 실행하면 현재 사용자의 아키텍처에 맞는 앱이 출력됩니다.

```sh
AppleApp/Tools/build-preview-mac.sh ../build
```

`CoreaVPN_TEST`와 FlClash를 설정한 Mac에서는 미리보기 앱을 종료하고 다음 명령으로 검사 도구를 설치합니다. `--migrate-from ..`은 이전 작업공간에서 이 앱의 최근 검사 기록을 가져옵니다.

```sh
python3 -B AppleApp/Tools/install-preview-runtime.py ../build --migrate-from ..
mkdir -p "$HOME/Applications"
ditto ../build/CoreaVPN.app "$HOME/Applications/CoreaVPN.app"
open "$HOME/Applications/CoreaVPN.app"
```

앱과 Terminal은 설치 후 `~/Library/Application Support/CoreaVPN/LocalRuntime`에서 도구를 실행하고 그 안의 `runs`에 새 기록을 저장합니다. 다음 빌드도 같은 경로에 설치합니다.

## Apple Silicon Mac용 서명 및 공증

Mac 배포용 앱 ID는 `net.petterwooju.coreavpn.client`이고 시스템 확장 ID는 `net.petterwooju.coreavpn.client.routing`입니다. 두 대상의 팀과 앱 그룹을 일치시키고 Personal VPN, Network Extensions 및 System Extension 권한을 프로비저닝합니다. 소스 빌드에 Xcode와 Go가 필요합니다. 실제 앱 설치 후에는 이 개발 도구를 사용하지 않습니다.

계정 소유자가 발급한 Developer ID Application 인증서와 개인 키를 키체인에 설치하고 공증 프로필을 준비합니다. 인수는 팀 ID, 공증 프로필 이름, 새 출력 폴더입니다. 스크립트는 arm64 네트워크 코어와 앱을 아카이브한 뒤 두 번들의 서명·프로파일과 Apple 공증 결과를 확인합니다. [Apple 인증서 발급 안내](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)

```sh
AppleApp/Tools/package-mac.sh TEAM_ID NOTARY_PROFILE ../CoreaVPN-release
```

Apple Silicon Mac에서 처음 빌드할 때는 전체 Xcode와 Go 1.26.3 이상을 준비하고 저장소 루트에서 다음 명령을 실행합니다. 첫 명령은 `go.mod`와 `go.sum`에 지정된 의존성으로 시스템 확장의 정적 라이브러리를 생성합니다. 새 Mac에서는 첫 빌드에 의존성을 다운로드할 인터넷 연결이 필요합니다.

```sh
AppleApp/TransportPrototype/build-archive.sh macosx .build/routing/macosx arm64
xcodebuild -project CoreaVPN.xcodeproj -scheme CoreaVPN -destination 'generic/platform=macOS' ARCHS=arm64 build
```

서명 준비 전 컴파일만 확인하려면 두 번째 명령에 `CODE_SIGNING_ALLOWED=NO`를 추가합니다. iPhone용 기본 앱은 Go 코어 없이 `xcodebuild -project CoreaVPN.xcodeproj -scheme CoreaVPN -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build`로 확인할 수 있습니다. 실기기 VPN을 사용하려면 위의 팀 서명이 필요합니다.

## 연결과 측정

**.net 주소 중계 켜기**를 누르면 현재 물리 회선에서 지정된 호스트 17개의 공인 IPv4를 조회합니다. 앱 내부에서만 사용하는 DNS 중계이며 시스템 DNS 설정을 변경할 필요가 없습니다. 앱이 활성 상태인 동안 DNS 응답의 유효기간과 회선 변경을 확인합니다. iPhone이 잠들면 운영체제가 저장된 접속 주소를 사용하므로, 주소 변경 후 재연결에 실패한 경우 앱을 다시 엽니다.

Mac의 빠른 연결은 계정에서 가능한 경우 Leo부터 시작합니다. **168.126.63.1 100ms 이하 서버 연결**은 ping 20회 중 18회 이상 응답하고 평균 왕복 지연이 100ms 이하인 첫 서버를 유지합니다. **FAST 다운로드 10Mbps 이상 서버 연결**은 터널에서 확인한 원본 다운로드 속도가 10Mbps 이상인 첫 서버를 유지합니다. 업로드와 HTTPS 지연은 별도로 기록합니다.

Mac에서 **전체 테스트 후 서버 선택**을 누르면 계정 그룹 설정과 관계없이 매번 A~E 그룹의 23개 서버에 차례로 연결을 시도합니다. D 그룹의 `.com` 서버 4개와 E 그룹의 `.kr` 서버 2개도 포함합니다. 각 터널이 연결되면 ping과 Cloudflare HTTPS를 순서대로 측정합니다. 연결이나 측정이 실패하면 해당 서버 행에서 실패 단계를 확인할 수 있습니다. 비교표에서 다운로드 속도, 응답 수, ping 지연, 업로드 속도 및 HTTPS 지연을 비교하고, 이전 네트워크가 복구되면 원하는 서버의 **연결**을 누릅니다. **검사 중지**는 완료한 항목을 보존하고, **CoreaVPN 해제**는 유지 중인 연결과 자동 재연결을 해제합니다.

**측정 기록**에서는 회선을 선택해 검사별 결과와 누적 순위를 확인하고 CSV를 내보낼 수 있습니다. 기본으로 포함한 2026년 11월 25일 베이징 사무실 기준선은 당시 Mac의 en6 회선에서 측정했습니다. 해당 Mac을 같은 사무실 유선망에서 사용할 때만 설정에서 기존 기록을 현재 회선에 연결합니다.

## FlClash가 인터넷 연결을 유지하는 Mac

미리보기 앱의 **CoreaVPN_TEST**에서 빠른 연결 버튼을 누르면 전용 프로필로 검사를 시작합니다. 사용 가능한 서버 중 Leo를 먼저 검사하고 이후에는 이 회선에서 기록한 순위대로 진행합니다. `.net` 서버는 물리 회선의 DNS-over-HTTPS로 공인 IPv4를 조회하고, 원격 ID에는 공식 호스트 이름을 사용합니다. macOS에 미리 설치한 프로필, 승인된 손쉬운 사용 도우미와 FlClash 화면 좌표 파일이 필요합니다. 저장소 루트에서 `AppleApp/Tools/build-local-quick.sh ../build`로 도우미 두 개를 빌드한 뒤 미리보기 앱을 빌드합니다.

**연결 → CoreaVPN_TEST로 Puma 측정 → Puma 측정 방식**에서 단독 진단 방법을 선택합니다. 빠른 연결은 누른 버튼에 해당하는 방법을 사용합니다.

| 측정 방식 | 측정 대상과 결과 | 빠른 연결의 합격 기준 |
|---|---|---|
| FAST 방식 (HTTPS) | Cloudflare 측정 서버까지 다운로드·업로드 Mbps, 평상시와 전송 중 HTTPS 지연 | 터널을 통해 검증한 다운로드 10Mbps 이상 |
| ICMP ping (168.126.63.1) | 해당 IP까지 ping 왕복 지연, 응답 수와 손실률 | 20회 중 18회 이상 응답, 평균 100ms 이하 |

두 방식 모두 측정 대상까지의 IKEv2 터널 경로를 확인합니다. Terminal에서 Puma 또는 전체 후보를 검사할 때는 `Run-Puma.command`, `Run-CoreaVPN-23.command`, `Run-CoreaVPN-All.command`에 `--measurement https` 또는 `--measurement icmp`를 지정합니다. 인수를 생략하면 HTTPS로 측정합니다.

FAST 방식의 후보당 테스트 데이터 상한은 다운로드 16 MiB, 업로드 4 MiB이며 준비 전송과 프로토콜 오버헤드가 추가됩니다. Cloudflare에서 보이는 출구 IP와 경로에 따라 측정 지점이 달라질 수 있습니다. [Cloudflare 측정 엔드포인트](https://github.com/cloudflare/speedtest/blob/main/README.md)

로컬 감시 프로세스는 앱을 닫아도 동작합니다. 합격 후에는 물리 회선과 측정 서버까지의 터널 경로로 연결 상태를 확인합니다. 검사 도중 **검사 중지**를 누르면 완료한 서버의 결과를 저장하고 FlClash를 복구합니다. 합격 연결의 해제, 후보 소진, 연결 이상도 복구로 이어집니다.

Puma만 검사하려면 **연결** 화면의 **CoreaVPN_TEST로 Puma 측정**에서 연결 버튼을 누릅니다. 관리자 암호는 Terminal의 `sudo` 프롬프트에 입력합니다. 검사 도구는 전용 프로필의 원래 서버 주소와 원격 ID를 저장하고 독립 복구 프로세스를 준비한 뒤 FlClash를 일시 정지합니다. Puma 측정을 마치거나 중지하면 두 필드와 DNS를 원래 값으로 돌리고 FlClash 엔진, TUN, 시스템 프록시 및 인터넷 연결을 확인합니다.

앱에서 선택한 방식의 결과, 복구 상태와 실행 폴더를 확인합니다. 측정 기록은 HTTPS와 ICMP별로 순위를 계산합니다. **설정**에서 회선 이름을 입력하면 같은 회선의 복구까지 확인한 Puma 결과를 자동 저장합니다. 이전 실행은 **현재 회선 기록에 추가**에서 측정 당시 회선을 확인한 후 한 번만 가져옵니다.

현재 FlClash TUN이나 시스템 프록시가 활성 상태이면 기본 앱은 기존 연결을 보존하고 측정을 중단합니다. 이 Mac에서 Puma를 시험하려면 먼저 앱에 계정을 저장하고 VPN 구성을 승인합니다. 독립 복구 프로세스가 준비된 뒤에만 FlClash를 일시 정지하는 전용 도구가 있습니다. 이 도구는 기존 `coreavpn-macos` 스킬의 컴파일된 UI 도우미 및 현재 화면 배치에 맞는 FlClash 좌표 파일을 사용합니다.

```sh
python3 -B AppleApp/Tools/native-puma-pilot.py \
  --app "/path/to/signed/CoreaVPN.app" \
  --ui "/path/to/authorized/offline-ui" --fl-map "/path/to/fl-map.json" \
  --log-dir "/path/to/new-run" --run
```

실행 결과에서 `native-ping.json`은 실제 ping 표본을, `native-recovered.json`은 FlClash와 인터넷 연결의 복구 결과를 담습니다. 터널을 시작할 수 없거나 복구가 실패하면 종료 코드가 0이 아닙니다.

## 규칙 및 경로 실험

**규칙 → 가져오기**에서 현재 FlClash 설정을 선택합니다. 원래 순서, 정책 이름 및 그룹 참조를 유지합니다. 사용자는 규칙을 추가하거나 편집하고 우선순위를 바꿀 수 있습니다. 공유용 규칙 JSON에는 구독 주소와 프록시 암호가 들어가지 않습니다. Mac 배포용 앱에서는 **프록시 그룹 설정**에서 노드 인증 정보를 이 Mac의 키체인에 저장하고 **규칙 적용**으로 투명 프록시 확장을 활성화합니다. 사용 가능한 노드와 인증 설정이 필요합니다.

`CoreaVPNLab`은 별도 스킴입니다. 명시적으로 지정한 목적지의 트래픽을 사용자의 규칙에 따라 Direct, CoreaVPN 또는 지정한 기존 프록시로 보내는 패킷 터널 확장을 포함합니다. iPhone에서 프로세스명으로 앱을 식별할 수 없습니다. Mac의 규칙 미리보기에서는 프로세스 조건을 평가할 수 있고, IP 패킷만 받는 실험 확장에서는 해당 조건의 출구를 확정할 수 없습니다. 도메인 접미사에 속한 서비스를 시험할 때는 실제 접속할 호스트 이름을 지정합니다. 공유 주소에 서로 다른 출구가 지정되면 충돌을 알립니다.

Go 및 Apple SDK가 설치된 Mac에서 저장소 루트를 기준으로 대상에 맞는 라이브러리를 빌드합니다. `Go` 실행 파일을 별도로 설치한 경우 `GO` 환경 변수에 절대 경로를 지정할 수 있습니다.

```sh
AppleApp/TransportPrototype/build-archive.sh iphoneos .build/route-lab/iphoneos
AppleApp/TransportPrototype/build-archive.sh macosx .build/route-lab/macosx
AppleApp/TransportPrototype/build-archive.sh iphonesimulator .build/route-lab/iphonesimulator
```

Xcode에서 `CoreaVPNLab`과 `ScopedTunnel`을 같은 팀으로 서명합니다. 두 대상의 공유 Keychain 그룹과 확장 번들 ID가 일치해야 합니다. 이 실험 패키지는 개인 개발용입니다. Mac의 Developer ID 직접 배포에는 Apple이 지원하는 시스템 확장 패키지가 별도로 필요합니다. [Apple의 VPN 확장 배포 방식](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)

**터널 실험 → 기존 프록시 그룹 연결 설정**에서 원래 FlClash 설정을 기기에서 직접 열고 각 그룹에 쓸 노드를 선택합니다. 사용하는 노드의 접속 설정만 공유 Keychain에 보관합니다. Shadowsocks와 AnyTLS를 지원합니다. 원래 AnyTLS 노드에서 인증서 검증을 생략하고 있다면 공급자의 인증서 이름이나 확인한 SHA-256 지문을 지정해야 합니다. 실험 터널의 CoreaVPN 경로는 서버 인증서와 사용자 계정을 사용하는 EAP 방식으로 연결합니다.

## 개발 검증

2026년 11월 25일 베이징 사무실 Mac의 `en6`에서 FlClash를 켠 채 앱의 DNS 코드로 17개 `.net` 서버의 공인 IPv4를 모두 확인했습니다. 19시 7분에는 미리보기 앱의 버튼으로 기존 Puma 프로필을 연결했습니다. `ipsec0`을 통해 보낸 ping 20회 중 6회가 응답했고 평균 지연은 167.235ms였습니다. Puma 해제, DNS 복원, E_VENUS 해제 상태, FlClash 엔진과 TUN, 시스템 프록시의 30초 안정 상태 및 HTTPS 응답을 확인했습니다.

현재 FlClash 설정에서 규칙 1,775개와 그룹 19개를 읽었고, 선택한 Shadowsocks 노드에서 HTTPS와 UDP 응답을 확인했습니다. 확인한 AnyTLS 노드는 기존 SNI로 인증서를 검증할 수 없어 연결이 중단됐습니다. 전체 규칙의 실기기 적용, 앱이 생성한 Personal VPN 구성의 실기기 측정은 검증이 남아 있습니다. Mac에 설치한 Xcode의 iPhone 17 Pro 시뮬레이터에서 기본 앱을 실행했습니다.

저장소 루트에서 아래 명령으로 물리 VPN 전환 없이 측정, DNS, 프로필, 규칙 및 복구 테스트를 실행합니다. 선택적으로 마지막 인수에 현재 FlClash YAML 경로를 넣어 실제 구성도 검사할 수 있습니다. Go 테스트는 별도의 로컬 프록시와 가상 IP 패킷으로 패킷 전송을 확인합니다.

```sh
AppleApp/Tools/check.sh
(cd AppleApp/TransportPrototype && go test ./...)
(cd AppleApp/TransportPrototype && go test -tags loopback_fixture -run TestEncryptedShadowsocksPacketFlow ./packetproxy)
```
