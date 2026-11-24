---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: CE에서 EE로의 변환 문제 해결
---

GitLab Community Edition에서 GitLab Enterprise Edition으로 Linux 패키지 설치를 변환할 때 다음과 같은 문제가 발생할 수 있습니다.

## RPM '패키지가 이미 설치됨' 오류 {#rpm-package-is-already-installed-error}

RPM을 사용하는 경우 다음과 같은 오류가 발생할 수 있습니다:

```shell
package gitlab-7.5.2_omnibus.5.2.1.ci-1.el7.x86_64 (which is newer than gitlab-7.5.2_ee.omnibus.5.2.1.ci-1.el7.x86_64) is already installed
```

`--oldpackage` 옵션을 사용하여 이 버전 확인을 재정의할 수 있습니다:

```shell
sudo rpm -Uvh --oldpackage gitlab-7.5.2_ee.omnibus.5.2.1.ci-1.el7.x86_64.rpm
```

## 설치된 패키지로 인해 사용되지 않는 패키지 {#package-obsoleted-by-installed-package}

Community Edition(CE) 및 Enterprise Edition(EE) 패키지는 서로 사용되지 않는 것으로 표시되어 두 패키지가 동시에 설치되지 않습니다.

로컬 RPM 파일을 사용하여 CE에서 EE로 전환하거나 그 반대로 전환하는 경우 `rpm`을(를) 사용하여 `yum` 대신 패키지를 설치하세요. yum을 사용하려고 하면 다음과 같은 오류가 발생할 수 있습니다:

```plaintext
Cannot install package gitlab-ee-11.8.3-ee.0.el6.x86_64. It is obsoleted by installed package gitlab-ce-11.8.3-ce.0.el6.x86_64
```

이 문제를 방지하려면 다음 중 하나를 수행합니다:

- [다운로드한 패키지로 업그레이드](../package/_index.md#upgrade-with-a-downloaded-package) 섹션에 제공된 지침과 동일한 지침을 사용합니다.
- 명령에 제공된 옵션에 `--setopt=obsoletes=0`을(를) 추가하여 yum에서 이 확인을 일시적으로 비활성화합니다.

## 프로젝트 리포지토리 설정에 액세스할 때 500 오류 {#500-error-when-accessing-project-repository-settings}

이 오류는 GitLab이 Community Edition(CE)에서 Enterprise Edition(EE)으로 변환된 후 CE로 변환되었다가 다시 EE로 변환될 때 발생합니다.

프로젝트의 리포지토리 설정을 볼 때 로그에서 이 오류를 볼 수 있습니다:

```shell
Processing by Projects::Settings::RepositoryController#show as HTML
  Parameters: {"namespace_id"=>"<namespace_id>", "project_id"=>"<project_id>"}
Completed 500 Internal Server Error in 62ms (ActiveRecord: 4.7ms | Elasticsearch: 0.0ms | Allocations: 14583)

NoMethodError (undefined method `commit_message_negative_regex' for #<PushRule:0x00007fbddf4229b8>
Did you mean?  commit_message_regex_change):
```

이 오류는 EE로의 초기 이동 시 CE 인스턴스에 EE 기능이 추가되어 발생합니다. 인스턴스가 CE로 다시 이동한 후 다시 EE로 업그레이드되면 `push_rules` 테이블이 데이터베이스에 이미 존재합니다. 따라서 마이그레이션은 `commit_message_regex_change` 열을 추가할 수 없습니다.

이로 인해 [EE 테이블의 백포트 마이그레이션](https://gitlab.com/gitlab-org/gitlab/-/blob/cf00e431024018ddd82158f8a9210f113d0f4dbc/db/migrate/20190402150158_backport_enterprise_schema.rb#L1619)이(가) 올바르게 작동하지 않습니다. 백포트 마이그레이션은 CE를 실행할 때 데이터베이스의 특정 테이블이 존재하지 않는다고 가정합니다.

이 문제를 해결하려면:

1. 데이터베이스 콘솔을 시작합니다:

   ```shell
   sudo gitlab-rails dbconsole --database main
   ```

1. 누락된 `commit_message_negative_regex` 열을 수동으로 추가합니다:

   ```sql
   ALTER TABLE push_rules ADD COLUMN commit_message_negative_regex VARCHAR;

   # Exit psql
   \q
   ```

1. GitLab을 다시 시작합니다:

   ```shell
   sudo gitlab-ctl restart
   ```
