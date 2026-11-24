---
stage: Verify
group: Runner Core
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments-to-other-projects-and-subjects>.
title: '자습서: 러너 승인 컨트롤러 빌드'
---

<!-- vale gitlab_base.FutureTense = NO -->

이 튜토리얼은 CI/CD 작업 실행을 위한 사용자 지정 정책을 적용하는 러너 승인 컨트롤러를 빌드하는 과정을 안내합니다. 작업 라우터에 연결되고 이미지 허용 목록 정책을 구현하는 Go 컨트롤러를 생성합니다.

이 튜토리얼의 코드 예제는 [runner-controller-example](https://gitlab.com/gitlab-org/cluster-integration/runner-controller-example) 리포지토리에서 적용되었으며, 시작점으로 사용할 수 있는 완전한 참조 구현을 제공합니다.

이 튜토리얼을 완료하면 다음을 수행하는 작동하는 승인 컨트롤러가 있습니다:

- gRPC를 사용하여 작업 라우터에 연결합니다
- GitLab에 자신을 등록합니다
- 작업 승인 요청을 수신합니다
- 사용자 지정 정책에 대해 작업을 평가합니다
- 승인 결정을 반환합니다

러너 승인 컨트롤러를 빌드하려면:

1. [GitLab에서 러너 컨트롤러 생성](#create-a-runner-controller-in-gitlab)
1. [러너 컨트롤러 범위 지정](#scope-the-runner-controller)
1. [러너 컨트롤러 토큰 생성](#create-a-runner-controller-token)
1. [Go 프로젝트 설정](#set-up-your-go-project)
1. [Protobuf 정의에서 클라이언트 코드 생성](#generate-client-code-from-protobuf-definitions)
1. [인증 구현](#implement-authentication)
1. [에이전트 등록 구현](#implement-agent-registration)
1. [승인 루프 구현](#implement-the-admission-loop)
1. [승인 정책 구현](#implement-an-admission-policy)
1. [드라이 런 상태로 테스트](#test-with-dry-run-state)
1. [프로덕션에서 활성화](#enable-in-production)

## 시작하기 전에 {#before-you-begin}

다음을 확인하세요:

- GitLab Self-Managed 또는 GitLab Dedicated(Ultimate 티어 포함)
- GitLab 인스턴스에 대한 관리자 액세스
- GitLab API와 상호작용하기 위해 다음 중 하나:
  - [GitLab CLI (`glab`)](https://docs.gitlab.com/cli/) 1.85.0 이상(`glab auth login`로 인증)
  - `curl` 또는 다른 HTTP 클라이언트
- Go 1.21 이상 설치
- Protobuf 코드 생성을 위해 설치된 [`buf` CLI](https://buf.build/docs/installation/)
- GitLab 인스턴스에서 활성화된 다음 기능 플래그:
  - `job_router`
  - `job_router_admission_control`
- GitLab Runner 18.9 이상(`FF_USE_JOB_ROUTER` 환경 변수가 `true`로 설정)

## GitLab에서 러너 컨트롤러 생성 {#create-a-runner-controller-in-gitlab}

[러너 컨트롤러 API](../../api/runner_controllers.md)를 사용하여 러너 컨트롤러를 생성합니다.

`dry_run` 상태로 시작하여 적용을 활성화하기 전에 컨트롤러 동작을 검증합니다:

{{< tabs >}}

{{< tab title="GitLab CLI" >}}

```shell
glab runner-controller create --description "Image allowlist controller" --state dry_run
```

{{< /tab >}}

{{< tab title="curl" >}}

```shell
curl --request POST \
     --header "PRIVATE-TOKEN: <your_access_token>" \
     --header "Content-Type: application/json" \
     --data '{"description": "Image allowlist controller", "state": "dry_run"}' \
     --url "https://gitlab.example.com/api/v4/runner_controllers"
```

{{< /tab >}}

{{< /tabs >}}

반환된 `id`을 다음 단계를 위해 저장합니다.

## 러너 컨트롤러 범위 지정 {#scope-the-runner-controller}

러너 컨트롤러는 승인 요청을 받기 위해 범위를 지정해야 합니다. 범위 없이는 컨트롤러가 활성화되어도 비활성 상태로 유지됩니다.

이 튜토리얼에서는 컨트롤러를 인스턴스의 모든 러너로 범위 지정합니다:

{{< tabs >}}

{{< tab title="GitLab CLI" >}}

```shell
glab runner-controller scope create <controller_id> --instance
```

{{< /tab >}}

{{< tab title="curl" >}}

```shell
curl --request POST \
     --header "PRIVATE-TOKEN: <your_access_token>" \
     --url "https://gitlab.example.com/api/v4/runner_controllers/<controller_id>/scopes/instance"
```

{{< /tab >}}

{{< /tabs >}}

또는 [러너 컨트롤러 API](../../api/runner_controllers.md)를 사용하여 컨트롤러를 특정 러너로 범위 지정할 수 있습니다. 컨트롤러가 특정 러너에 대해서만 작업을 평가하도록 하려면 러너 수준 범위 지정을 사용합니다.

## 러너 컨트롤러 토큰 생성 {#create-a-runner-controller-token}

작업 라우터를 사용하여 인증하기 위해 러너 컨트롤러에 대한 토큰을 생성합니다:

{{< tabs >}}

{{< tab title="GitLab CLI" >}}

```shell
glab runner-controller token create <controller_id> --description "Production token"
```

{{< /tab >}}

{{< tab title="curl" >}}

```shell
curl --request POST \
     --header "PRIVATE-TOKEN: <your_access_token>" \
     --header "Content-Type: application/json" \
     --data '{"description": "Production token"}' \
     --url "https://gitlab.example.com/api/v4/runner_controllers/<controller_id>/tokens"
```

{{< /tab >}}

{{< /tabs >}}

반환된 `token` 값을 안전하게 저장합니다. 토큰은 한 번만 표시됩니다.

## Go 프로젝트 설정 {#set-up-your-go-project}

새 Go 프로젝트를 생성합니다:

```shell
mkdir runner-admission-controller
cd runner-admission-controller
go mod init example.com/runner-admission-controller
```

## Protobuf 정의에서 클라이언트 코드 생성 {#generate-client-code-from-protobuf-definitions}

[GitLab Agent for Kubernetes](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent) 리포지토리의 Protobuf 정의에서 gRPC 클라이언트 코드를 생성해야 합니다. 다음을 포함하여 선호하는 방법을 사용할 수 있습니다:

- `.proto` 파일을 수동으로 벤더링하고 `protoc`를 직접 사용합니다.
- [`buf`](https://buf.build/)를 사용하여 자동으로 코드를 가져오고 생성합니다.

Protobuf 정의에 대한 자세한 내용은 러너 컨트롤러 사양에서 [클라이언트 코드 생성](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/blob/master/doc/runner_controller.md#generating-client-code)을 참조하세요.

이 튜토리얼은 `buf`을 사용합니다. `buf.gen.yaml`를 생성합니다:

```yaml
version: v2

managed:
  enabled: true

  disable:
    - module: buf.build/bufbuild/protovalidate

  override:
    - file_option: go_package
      value: internal/rpc

inputs:
  - git_repo: https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent.git
    branch: master

plugins:
  - local: ["go", "run", "google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.10"]
    out: .
  - local: ["go", "run", "google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1"]
    out: .
```

코드를 생성합니다:

```shell
buf generate
```

이것은 `internal/rpc/`에서 gRPC 클라이언트 코드를 생성합니다.

## 인증 구현 {#implement-authentication}

러너 컨트롤러는 gRPC 메타데이터 헤더를 사용하여 작업 라우터로 인증합니다. 사양 세부사항은 러너 컨트롤러 사양에서 [인증](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/blob/master/doc/runner_controller.md#authentication)을 참조하세요.

필수 헤더를 포함하는 자격 증명 공급자를 생성합니다:

```go
type tokenCredentials struct {
    token string
}

func (t *tokenCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
    return map[string]string{
        "authorization":     "Bearer " + t.token,
        "gitlab-agent-type": "runnerc",
    }, nil
}

func (t *tokenCredentials) RequireTransportSecurity() bool {
    return true
}
```

gRPC 연결을 생성하려면 다음 코드를 사용합니다:

```go
conn, err := grpc.NewClient(kasAddress,
    grpc.WithTransportCredentials(credentials.NewTLS(nil)),
    grpc.WithPerRPCCredentials(&tokenCredentials{token: agentToken}),
)
```

## 에이전트 등록 구현 {#implement-agent-registration}

현재 상태 추적 및 모니터링을 위해 작업 라우터에 컨트롤러를 등록합니다. 현재 상태를 유지하기 위해 주기적으로(권장: 3분마다) 다시 등록합니다. 사양 세부사항은 러너 컨트롤러 사양에서 [AgentRegistrar](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/blob/master/doc/runner_controller.md#agentregistrar)을 참조하세요.

```go
func registerAgent(ctx context.Context, conn *grpc.ClientConn, instanceID int64) error {
    client := rpc.NewAgentRegistrarClient(conn)

    _, err := client.Register(ctx, &rpc.RegisterRequest{
        Meta: &rpc.Meta{
            Version:      "1.0.0",
            GitRef:       "main",
            Architecture: runtime.GOARCH,
        },
        InstanceId: instanceID,
    })
    return err
}
```

## 승인 루프 구현 {#implement-the-admission-loop}

승인 루프는 작업 라우터에서 작업 세부사항을 수신하고 결정을 전송합니다. 사양 세부사항은 러너 컨트롤러 사양에서 [RunnerControllerService](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/blob/master/doc/runner_controller.md#runnercontrollerservice) 및 [프로토콜 흐름](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/blob/master/doc/runner_controller.md#protocol-flow)을 참조하세요.

```go
func handleAdmissionRequest(ctx context.Context, client rpc.RunnerControllerServiceClient) error {
    admissionCtx, cancel := context.WithCancel(ctx)
    defer cancel()

    stream, err := client.AdmitJob(admissionCtx)
    if err != nil {
        return err
    }

    // Wait for admission request
    req, err := stream.Recv()
    if err != nil {
        return err
    }

    // Evaluate the job (implement your policy here)
    admitted, reason := evaluateJob(req)

    // Send decision
    var resp *rpc.AdmitJobResponse
    if admitted {
        resp = &rpc.AdmitJobResponse{
            AdmissionResponse: &rpc.AdmitJobResponse_Admitted{Admitted: &rpc.Admitted{}},
        }
    } else {
        resp = &rpc.AdmitJobResponse{
            AdmissionResponse: &rpc.AdmitJobResponse_Rejected{
                Rejected: &rpc.Rejected{Reason: reason},
            },
        }
    }

    if err := stream.Send(resp); err != nil {
        return err
    }

    _ = stream.CloseSend()
    var x any
    err = stream.RecvMsg(x) // consume EOF
    if err != io.EOF {
      return err
    }

    return nil
}
```

## 승인 정책 구현 {#implement-an-admission-policy}

사용자 지정 정책 논리를 구현합니다. 이 예제는 `:latest` 태그가 있는 이미지를 거부합니다:

```go
func evaluateJob(req *rpc.AdmitJobRequest) (admitted bool, reason string) {
    imageName := req.GetImage().GetName()

    // Reject :latest tags
    if strings.HasSuffix(imageName, ":latest") {
        return false, "images with :latest tag are not allowed"
    }

    // Check allowlist
    allowed := []string{"alpine", "ubuntu", "golang", "ruby", "node", "python"}
    for _, prefix := range allowed {
        if strings.HasPrefix(imageName, prefix) {
            return true, ""
        }
    }

    return false, fmt.Sprintf("image %s is not in the approved list", imageName)
}
```

## 드라이 런 상태로 테스트 {#test-with-dry-run-state}

컨트롤러가 실행 중이고 `dry_run` 상태일 때 CI/CD 파이프라인을 트리거합니다. 컨트롤러 로그를 확인하여 승인 요청을 받는지 확인합니다. 작업 라우터는 결정을 기록하지만 드라이 런 상태의 컨트롤러에는 적용하지 않습니다. 이 작업을 통해 적용을 활성화하기 전에 동작을 검증하고 배포 위험을 줄일 수 있습니다.

## 프로덕션에서 활성화 {#enable-in-production}

`dry_run` 상태에서 컨트롤러 동작을 검증한 후 `enabled` 상태로 업데이트합니다:

{{< tabs >}}

{{< tab title="GitLab CLI" >}}

```shell
glab runner-controller update <controller_id> --state enabled
```

{{< /tab >}}

{{< tab title="curl" >}}

```shell
curl --request PUT \
     --header "PRIVATE-TOKEN: <your_access_token>" \
     --header "Content-Type: application/json" \
     --data '{"state": "enabled"}' \
     --url "https://gitlab.example.com/api/v4/runner_controllers/<controller_id>"
```

{{< /tab >}}

{{< /tabs >}}

이제 승인 결정이 작업 실행에 영향을 미칩니다.

### 러너 컨트롤러 호스팅 {#hosting-the-runner-controller}

러너 컨트롤러 호스팅은 GitLab 인스턴스의 규모와 승인 제어의 영향을 받는 작업의 로드에 따라 다릅니다. 유일한 요구사항은 GitLab 인스턴스가 러너 컨트롤러에서 도달 가능해야 한다는 것입니다. 왜냐하면 그것이 연결되는 곳이기 때문입니다.

## 다음 단계 {#next-steps}

- [완전한 예제 구현](https://gitlab.com/gitlab-org/cluster-integration/runner-controller-example)을 검토하세요.
- 프로토콜 세부사항은 [러너 컨트롤러 사양](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/blob/master/doc/runner_controller.md)을 읽으세요.
- 더 복잡한 정책을 위해 [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) 사용을 탐색하세요.
