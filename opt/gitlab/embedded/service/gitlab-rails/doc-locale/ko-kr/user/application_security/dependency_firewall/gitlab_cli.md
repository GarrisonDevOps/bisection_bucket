---
stage: Security Risk Management
group: Pipeline Security
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: GitLab CLI를 의존성 방화벽과 함께 사용
description: glab df 명령어를 사용하여 의존성 방화벽을 통해 패키지 관리자 실행
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed
- 상태:  베타

{{< /details >}}

[GitLab CLI](../../../editor_extensions/gitlab_cli/_index.md)는 의존성 방화벽을 통해 패키지 관리자를 실행합니다. `glab dependency-firewall` 접두사를 지원하는 모든 패키지 관리자 명령어에 추가하거나 더 짧은 별칭인 `glab df`을(를) 사용합니다:

```shell
glab df npm install
glab df pip install requests
glab df maven verify
```

구성할 사항이 없습니다. CLI는 Git 원격에서 프로젝트를 읽고 기존 `glab` 자격 증명으로 인증한 후 패키지 관리자가 이미 구성된 레지스트리를 사용합니다.

## 전제 조건 {#prerequisites}

- [GitLab CLI](../../../editor_extensions/gitlab_cli/_index.md)를 설치합니다.
- `glab auth login`로 인증합니다.
- 정책이 적용되는 GitLab 프로젝트를 가리키는 원격이 있는 Git 체크아웃에서 명령어를 실행합니다.
- 패키지 관리자 바이너리를 `PATH`에 배치합니다.

## 명령어의 작동 방식 {#how-the-commands-work}

각 `glab df` 명령어는 패키지 관리자 바이너리를 실행하고 모든 인수를 그대로 전달합니다. 관리자가 실행되는 동안 CLI는:

1. 로컬 검사 프록시를 시작하고 패키지 관리자 HTTPS 트래픽을 이를 통해 라우팅합니다.
1. 관리자가 요청하는 각 패키지 이름과 버전을 읽습니다.
1. GitLab에 해당 패키지를 프로젝트의 정책에 대해 평가하도록 요청합니다.
1. `403 Forbidden` 응답으로 차단된 패키지를 거부하고 허용되고 경고된 패키지는 통과시킵니다.
1. 차단되고 경고된 패키지를 `.gitlab/df/ci-log.json`에 기록하고 요약을 출력합니다.
1. 패키지 관리자 종료 코드로 종료합니다.

CLI는 `.npmrc`, `.yarnrc.yml`, `pip.conf`, `settings.xml`, `~/.gemrc` 또는 다른 레지스트리 구성을 수정하지 않습니다. 대신 그 사이의 트래픽을 검사합니다.

평가 결과는 단일 실행 동안 캐시되므로 의존성 트리에서 여러 번 나타나는 패키지는 한 번만 평가됩니다.

명령어는 다음 코드로 종료됩니다:

| 종료 코드 | 의미 |
|-----------|---------|
| 패키지 관리자 종료 코드 | 패키지 관리자가 실행되고 종료되었습니다. |
| `1`       | 패키지 관리자를 `PATH`에서 찾을 수 없거나 시작할 수 없습니다. CLI는 오류를 출력합니다. |
| `130`     | 예를 들어 <kbd>Control</kbd>+<kbd>C</kbd>로 실행이 중단되었습니다. |

CLI는 모든 실행(로컬 실행 포함)에서 `.gitlab/df/ci-log.json`을(를) 작업 디렉터리에 기록하므로 파일이 리포지토리에서 추적되지 않은 파일로 나타납니다. `.gitlab/df/`을(를) `.gitignore` 파일에 추가합니다.

## 실행 요약 읽기 {#read-the-run-summary}

패키지 관리자가 종료된 후 CLI는 방화벽이 경고하거나 차단한 모든 패키지의 테이블을 출력합니다:

```plaintext
╭────────────────────────────────────────────────────────────────────╮
│ ✖  GitLab Dependency Firewall                                      │
│ 1 blocked, 1 warning                                               │
├────────────────────────────────────────────────────────────────────┤
│    PACKAGE   VERSION  REASON                                       │
│ ✖  left-pad    1.3.0  Package 'left-pad' violates 'no-gpl' policy  │
│ ▲  lodash    4.17.15  Package 'lodash' violates 'high-risk' policy │
╰────────────────────────────────────────────────────────────────────╯
```

`✖`는 차단된 패키지를 표시하고 `▲`는 경고된 패키지를 표시합니다.

차단된 패키지가 하나 이상 있는 실행은 요약을 표준 오류로 출력합니다. 경고만 있는 실행은 요약을 표준 출력으로 출력합니다. CLI는 허용된 패키지를 기록하지 않으므로 경고나 차단이 없는 실행은 요약을 출력하지 않습니다.

## CI/CD에서 방화벽 사용 {#use-the-firewall-in-cicd}

작업 스크립트에서 패키지 관리자 명령어에 접두사를 추가합니다. 패키지 관리자가 실패하면 작업이 실패합니다. CLI가 해당 종료 코드를 전파하기 때문입니다:

```yaml
install:
  variables:
    GLAB_ENABLE_CI_AUTOLOGIN: "true"
  script:
    - glab df npm ci
```

CLI는 `GLAB_ENABLE_CI_AUTOLOGIN` CI/CD 변수가 `true`일 때만 CI/CD 작업 토큰으로 로그인합니다. 기본값은 `false`입니다. CLI는 또한 `GITLAB_CI=true`이(가) 필요합니다. GitLab이 모든 작업에서 이를 설정합니다. 변수가 설정되면 다른 자격 증명은 필요하지 않습니다.

작업 토큰은 자신의 프로젝트에 대해서만 패키지를 평가할 수 있습니다. GitLab은 다른 프로젝트의 토큰을 거부합니다. 작업을 트리거한 사용자는 프로젝트에서 최소한 보고자 역할 이상이어야 합니다.

방화벽 활동을 별도의 단계로 보고하려면 `glab df ci-summary`을(를) 사용합니다. `.gitlab/df/ci-log.json`을(를) 읽고 해당 디렉터리에서 모든 `glab df` 실행이 기록한 차단되고 경고된 패키지를 출력합니다:

```yaml
install:
  variables:
    GLAB_ENABLE_CI_AUTOLOGIN: "true"
  script:
    - glab df npm ci
    - glab df pip install -r requirements.txt
  after_script:
    - glab df ci-summary
```

`glab df ci-summary`은(는) 다음 종료 코드를 사용합니다:

| 종료 코드 | 의미 |
|-----------|---------|
| `0`       | 로그에 차단된 패키지가 없습니다. |
| `1`       | 로그를 읽을 수 없습니다. |
| `3`       | 로그에 차단된 패키지가 하나 이상 있습니다. |

`glab df ci-summary`을(를) 로그를 작성한 `glab df` 명령어와 같은 디렉터리에서 실행합니다. 그렇지 않으면 로그를 찾지 못하고 차단된 것이 없다고 보고하며 `0`로 종료됩니다.

항목은 실행 전반에 걸쳐 누적되고 CLI는 항목을 절대 지우지 않습니다. 이전 실행의 차단은 `.gitlab/df/ci-log.json`을(를) 삭제할 때까지 `glab df ci-summary`이(가) `3`로 종료되도록 유지합니다. 파일을 읽을 수 없으면 CLI는 그 자리에 두고 덮어쓰지 않으며 `glab df ci-summary`은(는) `1`로 종료됩니다.

모든 패키지를 평가하려면 작업 간에 패키지 관리자 캐시를 복원하지 않습니다. 캐시에서 복원된 패키지는 [평가되지 않습니다](_index.md#restrictions).

## 단일 패키지 확인 {#check-a-single-package}

`glab df package`을(를) 사용하여 프로젝트의 정책에 대해 하나의 패키지를 확인합니다. 패키지 관리자를 실행하지 않으며 패키지 관리자를 설치할 필요가 없습니다. 다른 명령어처럼 Git 원격에서 프로젝트를 확인합니다.

버전을 포함하는 패키지 URL(PURL)을 전달합니다. 지원되는 PURL 유형은 `npm`, `pypi`, `maven`, `gem`입니다:

```shell
glab df package pkg:npm/left-pad@1.3.0
glab df package pkg:pypi/requests@2.31.0
glab df package pkg:maven/org.slf4j/slf4j-api@2.0.13
glab df package pkg:gem/rails@7.1.3
```

`glab df package`은(는) 다음 종료 코드를 사용합니다:

| 종료 코드 | 의미 |
|-----------|---------|
| `0`       | 패키지가 허용되거나 경고됩니다. |
| `1`       | CLI가 잘못 구성되었거나 전송 오류가 발생했습니다. |
| `3`       | 패키지가 차단됩니다. |

명령어는 `.gitlab/df/ci-log.json`에 기록하지 않으므로 `glab df ci-summary`은(는) 해당 결과를 포함하지 않습니다.

## GitLab이 패키지를 평가할 수 없는 경우 {#when-gitlab-cant-evaluate-a-package}

CLI는 완료할 수 없는 평가를 두 가지 방식으로 처리합니다.

### CLI가 패키지를 차단 {#the-cli-blocks-the-package}

평가 요청이 실패하면 CLI는 패키지를 차단합니다. 요청은 네트워크 오류, 60초 후 시간 초과, 서버 오류(`503`), 속도 제한(`429`), 또는 권한 오류(`403`) 때문에 실패합니다. 예를 들어 보고자 역할이 없을 때입니다. 요약의 이유는 `policy check failed:`로 시작합니다.

CLI는 같은 실행에서 패키지가 다시 요청될 때 실패한 확인을 다시 시도합니다.

### CLI가 모든 패키지를 허용 {#the-cli-allows-every-package}

GitLab이 방화벽이 프로젝트를 평가하지 않는다고 응답하면 CLI는 나머지 실행 동안 모든 패키지를 허용합니다. 방화벽이 꺼져 있거나 GitLab이 프로젝트를 찾을 수 없거나 토큰이 이에 액세스할 수 없을 때 발생합니다. CLI는 `dependency firewall not evaluating`로 시작하는 한 줄을 표준 오류로 출력합니다.

잘못된 Git 원격 또는 프로젝트에 액세스할 수 없는 토큰은 따라서 모든 패키지를 허용합니다. 해당 라인의 출력을 확인합니다.

## 방화벽 없는 프로젝트 {#projects-without-the-firewall}

프로젝트에 대해 방화벽이 켜져 있지 않으면 `glab df` 명령어는 패키지 관리자를 평소대로 실행하고 평가하지 않습니다. CLI는 `dependency firewall not evaluating`로 시작하는 한 줄을 표준 오류로 출력합니다. 정책이 적용되는지 여부와 관계없이 모든 프로젝트에서 같은 명령어를 사용할 수 있습니다.
