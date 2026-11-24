---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 프로젝트를 Go 패키지로 사용
description: Go 모듈 및 import 호출.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [GitLab 17.3](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/161162)에서 인증되지 않은 `go get` 요청에 대해 404 오류를 반환하도록 변경되었습니다.
- [GitLab 19.4](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250766)에서 세분화된 개인 액세스 토큰을 지원하도록 변경되었습니다.

{{< /history >}}

사전 요구 사항:

- 하위 그룹에서 프라이빗 프로젝트를 Go 패키지로 사용하려면 [Go 요청을 인증](#authenticate-go-requests-to-private-projects)해야 합니다. 인증되지 않은 Go 요청으로 인해 `go get`가 실패합니다. 하위 그룹에 속하지 않은 프로젝트의 경우 Go 요청을 인증할 필요가 없습니다.

프로젝트를 Go 패키지로 사용하려면 `go get`과 `godoc.org` 검색 요청을 사용하세요. 메타 태그를 사용할 수 있습니다:

- [`go-import`](https://pkg.go.dev/cmd/go#hdr-Remote_import_paths)
- [`go-source`](https://github.com/golang/gddo/wiki/Source-Code-Links)

> [!note]
> 잘못된 HTTP 자격증명으로 `go get` 요청을 하면 404 오류가 발생합니다. HTTP 자격증명은 `~/.netrc`(MacOS 및 Linux) 또는 `~/_netrc`(Windows)에서 찾을 수 있습니다. Go 1.24 이상에서는 `GOAUTH` 환경 변수를 사용하여 자격증명을 제공할 수도 있습니다. 자세한 내용은 [`GOAUTH`로 인증](#authenticate-with-goauth)을 참조하세요.

## 프라이빗 프로젝트에 대한 Go 요청 인증 {#authenticate-go-requests-to-private-projects}

사전 요구 사항:

- GitLab 인스턴스는 HTTPS로 액세스할 수 있어야 합니다.
- 다음 중 하나를 가져야 합니다:
  - `read_api` 범위를 가진 [개인 액세스 토큰](../profile/personal_access_tokens.md).
  - 코드 리소스의 다운로드 권한을 가지며 프로젝트 범위로 제한되는 [세분화된 개인 액세스 토큰](../../auth/tokens/fine_grained_access_tokens.md).

### `GOAUTH`로 인증 {#authenticate-with-goauth}

Go 1.24 이상에서 [`GOAUTH` 환경 변수](https://pkg.go.dev/cmd/go@master#hdr-GOAUTH_environment_variable)를 사용하여 사용자 정의 명령으로 자격증명을 제공하세요.

> [!note]
> `git dir` 값은 `GOAUTH`에 대해 깊이가 1보다 큰 중첩된 하위 그룹의 프라이빗 프로젝트에는 작동하지 않습니다. 대신 사용자 정의 명령을 사용하세요.

`GOAUTH`로 인증하려면 Go 요청에 HTTP Basic 인증 헤더를 추가하는 사용자 정의 명령을 만드세요. 다음 예제는 `git credential fill`에서 반환된 Git over HTTPS 자격증명을 사용하여 `gitlab.com`에 대한 요청을 인증합니다:

```shell
#!/usr/bin/env bash
GITLAB_URL="https://gitlab.com"

creds=$(echo "url=${GITLAB_URL}" | git credential fill 2>&1) || {
  printf >&2 'error: git credential fill failed:\n%s\n' "$creds"
  exit 1
}

username=""
password=""
while IFS='=' read -r key value; do
  case "$key" in
    username) username="$value" ;;
    password) password="$value" ;;
  esac
done <<< "$creds"

if [ -z "$username" ] || [ -z "$password" ]; then
  printf >&2 'error: git credential fill did not return a username or password for %s\n' "$GITLAB_URL"
  exit 1
fi

encoded=$(printf '%s:%s' "$username" "$password" | base64 | tr -d '\n')

# Expected output format: https://pkg.go.dev/cmd/go@master#hdr-GOAUTH_environment_variable
printf '%s\n\nAuthorization: Basic %s\n\n' "$GITLAB_URL" "$encoded"
```

이 스크립트를 사용하려면:

1. 스크립트를 파일(예: `gitlab_goauth.sh`)에 저장하세요.
1. 파일을 실행 가능하게 만드세요:

   ```shell
   chmod +x gitlab_goauth.sh
   ```

1. `GOAUTH` 환경 변수를 명령의 절대 경로로 설정하세요:

   ```shell
   export GOAUTH="<absolute_path_to_your_command>"
   ```

또는 기존 `.netrc` 파일을 `GOAUTH`와 함께 사용하려면:

```shell
export GOAUTH="netrc"
```

### `.netrc`로 인증 {#authenticate-with-netrc}

[`.netrc`](https://everything.curl.dev/usingcurl/netrc.html) 파일로 Go 요청을 인증하려면 다음 정보로 파일을 만드세요:

```plaintext
machine gitlab.example.com
login <gitlab_user_name>
password <personal_access_token>
```

Windows에서는 Go가 `~/.netrc` 대신 `~/_netrc`을 읽습니다.

`go` 명령은 안전하지 않은 연결을 통해 자격증명을 전송하지 않습니다. Go에서 만든 HTTPS 요청을 인증하지만, Git을 통해 만든 요청은 인증하지 않습니다.

## Git 요청 인증 {#authenticate-git-requests}

Go가 프록시에서 모듈을 가져올 수 없으면 Git을 사용합니다. Git은 `.netrc` 파일을 사용하여 요청을 인증하지만 다른 인증 방법을 구성할 수 있습니다.

Git을 다음 중 하나로 구성하세요:

- 요청 URL에 자격증명을 포함하세요:

  ```shell
  git config --global url."https://${user}:${personal_access_token}@gitlab.example.com".insteadOf "https://gitlab.example.com"
  ```

- HTTPS 대신 SSH를 사용하세요:

  ```shell
  git config --global url."git@gitlab.example.com:".insteadOf "https://gitlab.example.com/"
  ```

## 프라이빗 프로젝트에 대한 Go 모듈 페칭 비활성화 {#disable-go-module-fetching-for-private-projects}

모듈이나 패키지를 가져오기 위해 Go는 환경 변수를 사용합니다:

- `GOPRIVATE`
- `GONOPROXY`
- `GONOSUMDB`

페칭을 비활성화하려면:

1. `GOPRIVATE`을 비활성화하세요:
   - 하나의 프로젝트에 대한 쿼리를 비활성화하려면 `GOPRIVATE=gitlab.example.com/my/private/project`을 비활성화하세요.
   - GitLab.com의 모든 프로젝트에 대한 쿼리를 비활성화하려면 `GOPRIVATE=gitlab.example.com`을 비활성화하세요.
1. `GONOPROXY`에서 프록시 쿼리를 비활성화하세요.
1. `GONOSUMDB`에서 체크섬 쿼리를 비활성화하세요.

- 모듈 이름이나 그 접두사가 `GOPRIVATE` 또는 `GONOPROXY`에 있으면 Go는 모듈 프록시를 쿼리하지 않습니다.
- 모듈 이름이나 그 접두사가 `GOPRIVATE` 또는 `GONOSUMDB`에 있으면 Go는 체크섬 데이터베이스를 쿼리하지 않습니다.

## 프라이빗 하위 그룹에 대한 Git 요청 인증 {#authenticate-git-requests-to-private-subgroups}

Go 모듈이 `gitlab.com/namespace/subgroup/go-module`과 같은 프라이빗 하위 그룹 아래에 있으면 Git 인증이 작동하지 않습니다. `go get`가 리포지토리 경로를 검색하는 인증되지 않은 요청을 수행하기 때문에 발생합니다. 인증 없이 GitLab은 `gitlab.com/namespace/subgroup.git`을 반환하여 인증되지 않은 사용자의 프로젝트 존재 노출의 보안 위험을 방지합니다. 결과적으로 Go 모듈을 다운로드할 수 없습니다.

[Go 인증을 구성](#authenticate-go-requests-to-private-projects)하여 프라이빗 하위 그룹에서 Go 모듈을 다운로드할 수 있습니다.

### 해결 방법: 모듈 이름에 `.git` 사용 {#workaround-use-git-in-the-module-name}

`go get` 요청을 건너뛰고 Go가 Git 인증을 직접 사용하도록 강제할 수 있는 방법이 있지만, 모듈 이름을 수정해야 합니다. [Go 설명서에서](https://go.dev/ref/mod#vcs-find):

> 모듈 경로에 경로 구성 요소의 끝에 VCS 한정자(`.bzr`, `.fossil`, `.git`, `.hg`, `.svn`)가 있으면 go 명령은 해당 경로 한정자까지의 모든 항목을 리포지토리 URL로 사용합니다. 예를 들어 모듈 `example.com/foo.git/bar`의 경우 go 명령은 `example.com/foo.git`에서 Git을 사용하여 리포지토리를 다운로드하며 bar 하위 디렉터리에서 모듈을 찾을 것으로 예상합니다.

1. 프라이빗 하위 그룹의 Go 모듈의 `go.mod`으로 이동하세요.
1. 모듈 이름에 `.git`을 추가하세요. 예를 들어 `module gitlab.com/namespace/subgroup/go-module`을 `module gitlab.com/namespace/subgroup/go-module.git`으로 이름 바꾸세요.
1. 이 변경 사항을 커밋하고 푸시하세요.
1. 이 모듈에 따라 다르는 Go 프로젝트를 방문하고 해당 `import` 호출을 조정하세요. 예를 들어, `import gitlab.com/namespace/subgroup/go-module.git`입니다.

Go 모듈은 이 변경 사항 후에 올바르게 페칭되어야 합니다. 예를 들어, `GOPRIVATE=gitlab.com/namespace/* go mod tidy`입니다.

## Geo 보조 사이트에서 Go 모듈 페치 {#fetch-go-modules-from-geo-secondary-sites}

[Geo](../../administration/geo/_index.md)를 사용하여 보조 Geo 서버에서 Go 모듈을 포함하는 Git 리포지토리에 액세스하세요.

Geo 보조 서버에 액세스하기 위해 SSH 또는 HTTP를 사용할 수 있습니다.

### SSH를 사용하여 Geo 보조 서버에 액세스 {#use-ssh-to-access-the-geo-secondary-server}

SSH로 Geo 보조 서버에 액세스하려면:

1. 클라이언트에서 Git을 재구성하여 주 서버의 트래픽을 보조 서버로 보내세요:

   ```shell
   git config --global url."git@gitlab-secondary.example.com".insteadOf "https://gitlab.example.com"
   git config --global url."git@gitlab-secondary.example.com".insteadOf "http://gitlab.example.com"
   ```

   - `gitlab.example.com`의 경우 주 사이트 도메인 이름을 사용하세요.
   - `gitlab-secondary.example.com`의 경우 보조 사이트 도메인 이름을 사용하세요.

1. 클라이언트가 GitLab 리포지토리에 대한 SSH 액세스로 설정되어 있는지 확인하세요. 주 서버에서 이를 테스트할 수 있으며 GitLab은 공개 키를 보조 서버로 복제합니다.

`go get` 요청은 주 Geo 서버에 HTTP 트래픽을 생성합니다. 모듈 다운로드가 시작되면 `insteadOf` 구성이 트래픽을 보조 Geo 서버로 보냅니다.

### HTTP를 사용하여 Geo 보조 서버에 액세스 {#use-http-to-access-the-geo-secondary}

보조 서버로 복제되는 지속적인 액세스 토큰을 사용해야 합니다. CI/CD 작업 토큰을 사용하여 HTTP로 Go 모듈을 페칭할 수 없습니다.

HTTP를 사용하여 Geo 보조 서버에 액세스하려면:

1. 클라이언트에 Git `insteadOf` 리디렉션을 추가하세요:

   ```shell
   git config --global url."https://gitlab-secondary.example.com".insteadOf "https://gitlab.example.com"
   ```

   - `gitlab.example.com`의 경우 주 사이트 도메인 이름을 사용하세요.
   - `gitlab-secondary.example.com`의 경우 보조 사이트 도메인 이름을 사용하세요.

1. [개인 액세스 토큰](../profile/personal_access_tokens.md)을 생성하고 클라이언트의 `~/.netrc` 파일에 자격증명을 추가하세요:

   ```shell
   machine gitlab.example.com login USERNAME password TOKEN
   machine gitlab-secondary.example.com login USERNAME password TOKEN
   ```

`go get` 요청은 주 Geo 서버에 HTTP 트래픽을 생성합니다. 모듈 다운로드가 시작되면 `insteadOf` 구성이 트래픽을 보조 Geo 서버로 보냅니다.
