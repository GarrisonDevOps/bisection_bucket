---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Auto DevOps를 위한 PostgreSQL 업그레이드
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

`POSTGRES_ENABLED`이 `true`일 때, Auto DevOps는 애플리케이션을 위한 [클러스터 내 PostgreSQL 데이터베이스](customize.md#postgresql-database-support)를 제공합니다.

PostgreSQL을 프로비저닝하는 데 사용되는 차트의 버전:

- 0.7.1부터 8.2.1까지 설정할 수 있습니다.

GitLab은 사용자가 데이터베이스를 새로운 PostgreSQL 차트로 마이그레이션하도록 권장합니다.

이 가이드는 PostgreSQL 데이터베이스를 마이그레이션하는 방법에 대한 지침을 제공하며, 다음을 포함합니다:

1. 데이터의 데이터베이스 덤프를 생성합니다.
1. 차트의 새 버전 8.2.1을 사용하여 새로운 PostgreSQL 데이터베이스를 설치하고 이전 PostgreSQL 설치를 제거합니다.
1. 데이터베이스 덤프를 새 PostgreSQL로 복원합니다.

## 전제 조건 {#prerequisites}

1. [`kubectl`](https://kubernetes.io/docs/tasks/tools/)을 설치합니다.
1. `kubectl`을 사용하여 Kubernetes 클러스터에 액세스할 수 있는지 확인합니다. 이는 Kubernetes 공급자에 따라 다릅니다.
1. 다운타임을 준비합니다. 아래 단계에는 데이터베이스 덤프를 생성한 후 클러스터 내 데이터베이스가 수정되지 않도록 애플리케이션을 오프라인 상태로 전환하는 것이 포함됩니다.
1. `POSTGRES_ENABLED`을 `false`로 설정하지 않았는지 확인합니다. 이 설정은 기존 채널 1 데이터베이스를 삭제합니다.

> [!note]
> Auto DevOps를 staging으로 구성한 경우, staging에서 먼저 백업 및 복원 단계를 시도하거나 검토 앱에서 시도해 보세요.

## 애플리케이션을 오프라인 상태로 전환 {#take-your-application-offline}

필요한 경우 데이터베이스 덤프를 생성한 후 데이터베이스가 수정되지 않도록 애플리케이션을 오프라인 상태로 전환합니다.

1. 환경에 대한 Kubernetes 네임스페이스를 가져옵니다. 일반적으로 `<project-name>-<project-id>-<environment>`과 같이 표시됩니다. 이 예제에서는 네임스페이스를 `minimal-ruby-app-4349298-production`이라고 합니다.

   ```shell
   $ kubectl get ns

   NAME                                                  STATUS   AGE
   minimal-ruby-app-4349298-production                   Active   7d14h
   ```

1. 사용 편의성을 위해 네임스페이스 이름을 내보냅니다:

   ```shell
   export APP_NAMESPACE=minimal-ruby-app-4349298-production
   ```

1. 다음 명령을 사용하여 애플리케이션의 배포 이름을 가져옵니다. 이 예제에서는 배포 이름이 `production`입니다.

   ```shell
   $ kubectl get deployment --namespace "$APP_NAMESPACE"
   NAME                  READY   UP-TO-DATE   AVAILABLE   AGE
   production            2/2     2            2           7d21h
   production-postgres   1/1     1            1           7d21h
   ```

1. 데이터베이스가 수정되지 않도록 다음 명령을 사용하여 배포의 복제본을 0으로 설정합니다. 이전 단계의 배포 이름을 사용합니다(`deployments/<DEPLOYMENT_NAME>`).

   ```shell
   $ kubectl scale --replicas=0 deployments/production --namespace "$APP_NAMESPACE"
   deployment.extensions/production scaled
   ```

1. 있는 경우 작업자의 복제본도 0으로 설정해야 합니다.

## 백업 {#backup}

1. PostgreSQL의 서비스 이름을 가져옵니다. 서비스의 이름은 `-postgres`으로 끝나야 합니다. 이 예제에서는 서비스 이름이 `production-postgres`입니다.

   ```shell
   $ kubectl get svc --namespace "$APP_NAMESPACE"
   NAME                     TYPE        CLUSTER-IP    EXTERNAL-IP   PORT(S)    AGE
   production-auto-deploy   ClusterIP   10.30.13.90   <none>        5000/TCP   7d14h
   production-postgres      ClusterIP   10.30.4.57    <none>        5432/TCP   7d14h
   ```

1. 다음 명령을 사용하여 PostgreSQL의 Pod 이름을 가져옵니다. 이 예제에서는 Pod 이름이 `production-postgres-5db86568d7-qxlxv`입니다.

   ```shell
   $ kubectl get pod --namespace "$APP_NAMESPACE" -l app=production-postgres
   NAME                                   READY   STATUS    RESTARTS   AGE
   production-postgres-5db86568d7-qxlxv   1/1     Running   0          7d14h
   ```

1. Pod에 다음과 같이 연결합니다:

   ```shell
   kubectl exec -it production-postgres-5db86568d7-qxlxv --namespace "$APP_NAMESPACE" -- bash
   ```

1. 연결된 후 다음 명령을 사용하여 덤프 파일을 생성합니다.

   - `SERVICE_NAME`은 이전 단계에서 얻은 서비스 이름입니다.
   - `USERNAME`은 PostgreSQL에 대해 구성한 사용자 이름입니다. 기본값은 `user`입니다.
   - `DATABASE_NAME`은 일반적으로 환경 이름입니다.
   - 데이터베이스 비밀번호를 묻는 메시지가 나타나면 기본값은 `testing-password`입니다.

     ```shell
     ## Format is:
     # pg_dump -h SERVICE_NAME -U USERNAME DATABASE_NAME > /tmp/backup.sql

     pg_dump -h production-postgres -U user production > /tmp/backup.sql
     ```

1. 백업 덤프가 완료되면 <kbd>Control</kbd>-<kbd>D</kbd> 또는 `exit`을 사용하여 Kubernetes exec 프로세스를 종료합니다.
1. 다음 명령을 사용하여 덤프 파일을 다운로드합니다:

   ```shell
   kubectl cp --namespace "$APP_NAMESPACE" production-postgres-5db86568d7-qxlxv:/tmp/backup.sql backup.sql
   ```

## 영구 볼륨 유지 {#retain-persistent-volumes}

기본적으로 PostgreSQL의 기본 데이터를 저장하는 데 사용되는 [영구 볼륨](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)은 해당 볼륨을 사용하는 Pod 및 Pod 클레임이 삭제될 때 `Delete`으로 표시됩니다.

이는 새로운 8.2.1 PostgreSQL을 선택할 때 이전의 0.7.1 PostgreSQL이 삭제되어 영구 볼륨도 함께 삭제되므로 중요합니다.

다음 명령을 사용하여 이를 확인할 수 있습니다:

```shell
$ kubectl get pv
NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                                                     STORAGECLASS   REASON   AGE
pvc-0da80c08-5239-11ea-9c8d-42010a8e0096   8Gi        RWO            Delete           Bound    minimal-ruby-app-4349298-staging/staging-postgres         standard                7d22h
pvc-9085e3d3-5239-11ea-9c8d-42010a8e0096   8Gi        RWO            Delete           Bound    minimal-ruby-app-4349298-production/production-postgres   standard                7d22h
```

이전의 0.7.1 PostgreSQL이 삭제되더라도 영구 볼륨을 유지하려면 보존 정책을 `Retain`로 변경합니다. 이 예제에서는 클레임 이름을 살펴보면 영구 볼륨 이름을 찾을 수 있습니다. `minimal-ruby-app-4349298` 애플리케이션의 staging 및 production 환경의 볼륨을 유지하려면 볼륨 이름은 `pvc-0da80c08-5239-11ea-9c8d-42010a8e0096` 및 `pvc-9085e3d3-5239-11ea-9c8d-42010a8e0096`입니다:

```shell
$ kubectl patch pv  pvc-0da80c08-5239-11ea-9c8d-42010a8e0096 -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'
persistentvolume/pvc-0da80c08-5239-11ea-9c8d-42010a8e0096 patched
$ kubectl patch pv  pvc-9085e3d3-5239-11ea-9c8d-42010a8e0096 -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'
persistentvolume/pvc-9085e3d3-5239-11ea-9c8d-42010a8e0096 patched
$ kubectl get pv
NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                                                     STORAGECLASS   REASON   AGE
pvc-0da80c08-5239-11ea-9c8d-42010a8e0096   8Gi        RWO            Retain           Bound    minimal-ruby-app-4349298-staging/staging-postgres         standard                7d22h
pvc-9085e3d3-5239-11ea-9c8d-42010a8e0096   8Gi        RWO            Retain           Bound    minimal-ruby-app-4349298-production/production-postgres   standard                7d22h
```

## 새 PostgreSQL 설치 {#install-new-postgresql}

> [!warning]
> 새로운 버전의 PostgreSQL을 사용하면 이전의 0.7.1 PostgreSQL이 삭제됩니다. 기본 데이터가 삭제되는 것을 방지하려면 [영구 볼륨](#retain-persistent-volumes)을 유지하도록 선택할 수 있습니다.

아래 단계를 수정하여 [범위](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable) 지정 `AUTO_DEVOPS_POSTGRES_CHANNEL`, `AUTO_DEVOPS_POSTGRES_DELETE_V1` 및 `POSTGRES_VERSION` 변수를 특정 환경(예: `staging`)으로 지정할 수 있습니다.

1. `AUTO_DEVOPS_POSTGRES_CHANNEL`을 `2`로 설정합니다. 이렇게 하면 새로운 8.2.1 기반 PostgreSQL을 사용하도록 선택하고 이전의 0.7.1 기반 PostgreSQL을 제거합니다.
1. `AUTO_DEVOPS_POSTGRES_DELETE_V1`을 공백이 아닌 값으로 설정합니다. 이 플래그는 데이터베이스의 실수로 삭제되는 것을 방지하는 보안장치입니다.
   <!-- DO NOT REPLACE when upgrading GitLab's supported version. This is NOT related to GitLab's PostgreSQL version support, but the one deployed by Auto DevOps. -->
1. `POSTGRES_VERSION`이 설정되어 있으면 `9.6.16` 이상으로 설정했는지 확인합니다. 이는 Auto DevOps에서 지원하는 최소 PostgreSQL 버전입니다. [사용 가능한 태그](https://hub.docker.com/r/bitnami/postgresql/tags)의 목록을 참고하세요.
1. `PRODUCTION_REPLICAS`을 `0`로 설정합니다. 다른 환경의 경우 `REPLICAS`을 [환경 범위](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable)와 함께 사용합니다.
1. `DB_INITIALIZE` 또는 `DB_MIGRATE` 변수를 설정한 경우 변수를 제거하거나 변수를 `XDB_INITIALIZE` 또는 `XDB_MIGRATE`으로 임시로 이름을 바꿔 효과적으로 비활성화합니다.
1. 브랜치에 대한 새 CI 파이프라인을 실행합니다. 이 경우 `main`에 대한 새 CI 파이프라인을 실행합니다.
1. 파이프라인이 성공하면 애플리케이션이 새 PostgreSQL이 설치된 상태로 업그레이드됩니다. 이 시점에는 복제본이 0개이므로 애플리케이션(새 데이터가 들어오는 것을 방지하기 위해)에 대한 트래픽이 제공되지 않습니다.

## 복원 {#restore}

1. 새 PostgreSQL의 Pod 이름을 가져옵니다. 이 예제에서는 Pod 이름이 `production-postgresql-0`입니다:

   ```shell
   $ kubectl get pod --namespace "$APP_NAMESPACE" -l app=postgresql
   NAME                      READY   STATUS    RESTARTS   AGE
   production-postgresql-0   1/1     Running   0          19m
   ````

1. 백업 단계의 덤프 파일을 Pod에 복사합니다:

   ```shell
   kubectl cp --namespace "$APP_NAMESPACE" backup.sql production-postgresql-0:/tmp/backup.sql
   ```

1. Pod에 연결합니다:

   ```shell
   kubectl exec -it production-postgresql-0 --namespace "$APP_NAMESPACE" -- bash
   ```

1. Pod에 연결한 후 다음 명령을 실행하여 데이터베이스를 복원합니다.

   - 데이터베이스 비밀번호를 묻는 메시지가 나타나면 기본값은 `testing-password`입니다.
   - `USERNAME`은 PostgreSQL에 대해 구성한 사용자 이름입니다. 기본값은 `user`입니다.
   - `DATABASE_NAME`은 일반적으로 환경 이름입니다.

   ```shell
   ## Format is:
   # psql -U USERNAME -d DATABASE_NAME < /tmp/backup.sql

   psql -U user -d production < /tmp/backup.sql
   ```

1. 복원이 완료된 후 데이터가 올바르게 복원되었는지 확인할 수 있습니다. `psql`을 사용하여 데이터의 현장 점검을 수행할 수 있습니다.

## 애플리케이션 복구 {#reinstate-your-application}

데이터베이스가 복원되었는지 확인한 후 다음 단계를 실행하여 애플리케이션을 복구합니다:

1. 이전에 제거하거나 비활성화한 경우 `DB_INITIALIZE` 및 `DB_MIGRATE` 변수를 복원합니다.
1. `PRODUCTION_REPLICAS` 또는 `REPLICAS` 변수를 원래 값으로 복원합니다.
1. 브랜치에 대한 새 CI 파이프라인을 실행합니다. 이 경우 `main`에 대한 새 CI 파이프라인을 실행합니다. 파이프라인이 성공하면 애플리케이션이 이전과 같이 트래픽을 처리해야 합니다.
