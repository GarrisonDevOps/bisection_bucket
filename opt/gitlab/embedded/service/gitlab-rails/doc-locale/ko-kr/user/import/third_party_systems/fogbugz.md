---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: FogBugz에서 마이그레이션
description: "FogBugz에서 GitLab으로 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

FogBugz 프로젝트를 GitLab으로 가져옵니다.

FogBugz 가져오기 도구는 원본 사안 번호 및 타임스탬프를 포함한 모든 사안과 의견을 가져옵니다. FogBugz 사용자를 GitLab 사용자로 매핑할 수 있습니다.

## 사전 요구 사항 {#prerequisites}

- [FogBugz 가져오기 원본](../../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources)을 활성화합니다. 활성화되지 않았으면 GitLab 관리자에게 활성화를 요청하세요. FogBugz 가져오기 원본은 GitLab.com에서 기본적으로 활성화됩니다.
- 가져올 대상 그룹에서 유지보수자 또는 소유자 역할.

## FogBugz에서 프로젝트 가져오기 {#import-project-from-fogbugz}

FogBugz에서 프로젝트를 가져오려면:

1. 오른쪽 상단 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 그리고 **새 프로젝트/리포지토리**를 선택합니다.
1. **프로젝트 가져오기**를 선택합니다.
1. **FogBugz**를 선택합니다.
1. FogBugz URL, 이메일 주소 및 비밀번호를 입력합니다.
1. FogBugz 사용자에서 GitLab 사용자로의 매핑을 생성합니다. 각 FogBugz 사용자의 경우:
   - FogBugz 계정을 전체 이름으로 매핑하되 GitLab 계정으로 매핑하지 않으려면 **GitLab 사용자** 텍스트 상자를 비워두세요. 이 매핑은 사용자의 전체 이름을 모든 이슈 및 의견의 설명에 추가하지만 이슈 및 의견을 프로젝트 생성자에게 할당합니다.
   - FogBugz 계정을 GitLab 계정으로 매핑하려면 **GitLab 사용자**에서 이슈 및 의견과 연결할 GitLab 사용자를 선택합니다.
1. 모든 사용자가 매핑되면 **다음 단계로 진행**을 선택합니다.
1. 프로젝트를 가져오려면:
   - 처음: **가져오기**를 선택합니다.
   - 다시: **다시 가져오기**를 선택합니다. 새 이름을 지정하고 **다시 가져오기**를 다시 선택합니다. 다시 가져오기는 원본 프로젝트의 새 복사본을 생성합니다.
1. 가져오기가 완료된 후 프로젝트 대시보드로 이동할 링크를 선택합니다. 기존 리포지토리를 푸시하기 위한 지시사항을 따릅니다.

## 관련 항목 {#related-topics}

- [가져오기 및 내보내기 설정](../../../administration/settings/import_and_export_settings.md).
- [가져오기를 위한 Sidekiq 구성](../../../administration/sidekiq/configuration_for_imports.md).
- [여러 Sidekiq 프로세스 실행](../../../administration/sidekiq/extra_sidekiq_processes.md).
- [특정 작업 클래스 처리](../../../administration/sidekiq/processing_specific_job_classes.md).
