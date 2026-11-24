---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Go 프록시 GitLab용(지원 중단됨)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- GitLab 13.1에서 [소개](https://gitlab.com/gitlab-org/gitlab/-/issues/27376)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `go_proxy`로 명명되었습니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../../policy/development_stages_support.md)입니다.
- GitLab 19.1에서 [지원 중단](https://gitlab.com/gitlab-org/gitlab/-/issues/592132)되었습니다.

{{< /history >}}

> [!warning]
> 이 기능은 GitLab 19.1에서 [지원 중단](https://gitlab.com/gitlab-org/gitlab/-/issues/592132)되었으며 20.0에서 제거될 예정입니다. 대신 [Go 가상 레지스트리](https://gitlab.com/gitlab-org/gitlab/-/issues/592136)를 사용하세요(사용 가능할 때).

GitLab용 Go 프록시를 사용하면 GitLab의 모든 프로젝트를 [Go 프록시 프로토콜](https://proxy.golang.org/)로 가져올 수 있습니다.

GitLab용 Go 프록시는 [실험](../../../policy/development_stages_support.md)이며 큰 리포지토리의 잠재적 성능 문제로 인해 프로덕션 사용을 위해 준비되지 않았습니다. [이슈 218083](https://gitlab.com/gitlab-org/gitlab/-/issues/218083)을 참조하세요.

GitLab은 Go 프록시가 활성화되어 있어도 패키지 레지스트리에 Go 모듈을 표시하지 않습니다. [이슈 213770](https://gitlab.com/gitlab-org/gitlab/-/issues/213770)을 참조하세요.

Go 프록시가 사용하는 특정 API 엔드포인트의 설명서는 [Go 프록시 API 설명서](../../../api/packages/go_proxy.md)를 참조하세요.

## GitLab을 Go 프록시로 추가 {#add-gitlab-as-a-go-proxy}

GitLab을 Go 프록시로 사용하려면 Go 1.13 이상을 사용해야 합니다.

사용 가능한 프록시 엔드포인트는 프로젝트별로 모듈을 가져오기 위한 것입니다: `/api/v4/projects/:id/packages/go`

GitLab에서 Go 모듈을 가져오려면 프로젝트별 엔드포인트를 `GOPROXY`에 추가하세요.

Go는 엔드포인트를 쿼리하고 기본 동작으로 대체합니다:

```shell
go env -w GOPROXY='https://gitlab.example.com/api/v4/projects/1234/packages/go,https://proxy.golang.org,direct'
```

이 구성으로 Go는 다음 순서대로 종속성을 가져옵니다:

1. Go는 프로젝트별 Go 프록시에서 가져오려고 시도합니다.
1. Go는 [`proxy.golang.org`](https://proxy.golang.org)에서 가져오려고 시도합니다.
1. Go는 버전 제어 시스템 작업(예: `git clone`, `svn checkout` 등)으로 직접 가져옵니다.

`GOPROXY`이 지정되지 않으면 Go는 2단계와 3단계를 따르며, 이는 `GOPROXY`을 `https://proxy.golang.org,direct`으로 설정하는 것과 같습니다. `GOPROXY`에 프로젝트별 엔드포인트만 포함되면 Go는 해당 엔드포인트만 쿼리합니다.

Go 환경 변수를 설정하는 방법에 대한 자세한 내용은 [환경 변수 설정](#set-environment-variables)을 참조하세요.

## 비공개 프로젝트에서 모듈 가져오기 {#fetch-modules-from-private-projects}

`go`은 안전하지 않은 연결을 통한 자격 증명 전송을 지원하지 않습니다. 다음 단계는 GitLab이 HTTPS로 구성되어 있는 경우에만 작동합니다:

1. GitLab용 Go 프록시에서 가져올 때 HTTP 기본 인증 자격 증명을 포함하도록 Go를 구성합니다.
1. 비공개 GitLab 프로젝트의 공개 체크섬 데이터베이스에서 체크섬 다운로드를 건너뛰도록 Go를 구성합니다.

### 요청 인증 활성화 {#enable-request-authentication}

범위를 `api` 또는 `read_api`으로 설정하여 [개인 액세스 토큰](../../profile/personal_access_tokens.md)을 생성합니다.

[`~/.netrc`](https://everything.curl.dev/usingcurl/netrc.html) 파일을 열고 다음 텍스트를 추가합니다. `< >`의 변수를 사용자의 값으로 바꿉니다.

잘못된 HTTP 자격 증명으로 `go get` 요청을 수행하면 404 오류가 표시됩니다.

> [!warning]
> `NETRC`라는 환경 변수를 사용하면 Go는 해당 값을 파일 이름으로 사용하고 `~/.netrc`을 무시합니다. GitLab CI/CD에서 `~/.netrc`을 사용하려는 경우 `NETRC`을 환경 변수 이름으로 사용하지 마세요.

```plaintext
machine <url> login <username> password <token>
```

- `<url>`: 예를 들어 `gitlab.com`인 GitLab URL입니다.
- `<username>`: 사용자 이름입니다.
- `<token>`: 개인 액세스 토큰입니다.

### 체크섬 데이터베이스 쿼리 비활성화 {#disable-checksum-database-queries}

Go 1.13 이상으로 종속성을 다운로드할 때 가져온 원본은 체크섬 데이터베이스 `sum.golang.org`에 대해 검증됩니다.

가져온 원본의 체크섬이 데이터베이스의 체크섬과 일치하지 않으면 Go는 종속성을 빌드하지 않습니다.

`sum.golang.org`이 비공개 모듈의 원본을 가져올 수 없기 때문에 비공개 모듈은 빌드에 실패하므로 체크섬을 제공할 수 없습니다.

이 문제를 해결하려면 `GONOSUMDB`을 비공개 프로젝트의 쉼표로 구분된 목록으로 설정합니다. Go 환경 변수 설정에 대한 자세한 내용은 [환경 변수 설정](#set-environment-variables)을 참조하세요.

예를 들어 `gitlab.com/my/project`에 대한 체크섬 쿼리를 비활성화하려면 `GONOSUMDB`을 설정합니다:

```shell
go env -w GONOSUMDB='gitlab.com/my/project,<previous value>'
```

## Go로 작업 {#working-with-go}

Go의 종속성 관리 또는 Go 전반에 익숙하지 않다면 다음 설명서를 검토하세요:

- [Go 모듈 참조](https://go.dev/ref/mod)
- [설명서(`golang.org`)](https://go.dev/doc/)
- [학습(`go.dev/learn`)](https://go.dev/learn/)

### 환경 변수 설정 {#set-environment-variables}

Go는 환경 변수를 사용하여 다양한 기능을 제어합니다. 일반적인 방법으로 이러한 변수를 관리할 수 있습니다. 하지만 Go 1.14는 Go 환경 변수를 특수 Go 환경 파일 `~/.go/env`로 읽고 씁니다(기본적으로).

- `GOENV`이 파일로 설정되면 Go는 대신 해당 파일로부터 읽고 쓰게 됩니다.
- `GOENV`이 설정되지 않았지만 `GOPATH`이 설정되면 Go는 `$GOPATH/env`을 읽고 씁니다.

Go 환경 변수는 `go env <var>`로 읽을 수 있으며 Go 1.14 이상에서는 `go env -w <var>=<value>`로 쓸 수 있습니다. 예를 들어 `go env GOPATH` 또는 `go env -w GOPATH=/go`입니다.

### 모듈 릴리스 {#release-a-module}

Go 모듈 및 모듈 버전은 Git, SVN, Mercurial과 같은 소스 리포지토리로 정의됩니다. 모듈은 `go.mod`과 Go 파일을 포함하는 리포지토리입니다. 모듈 버전은 버전 제어 시스템(VCS) 태그로 정의됩니다.

모듈을 게시하려면 `go.mod`과 소스 파일을 VCS 리포지토리에 푸시합니다. 모듈 버전을 게시하려면 VCS 태그를 푸시합니다.
