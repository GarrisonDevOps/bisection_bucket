---
stage: Security
group: Security Operations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "GitLab에서 보안 사건을 감지, 조사 및 대응합니다."
title: 보안 사건
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 보안 운영 팀은 GitLab Self-Managed 인스턴스의 관리자 및 유지 관리자와 GitLab.com의 그룹이 GitLab과 관련된 보안 사건을 감지하고 대응하도록 돕기 위해 이러한 권장 사항을 작성했습니다. 이를 사용하여 조직에서 정의한 보안 프로세스를 보완하되 대체하지 마세요.

감지와 대응은 함께 작동합니다:

1. 감지: 감사 이벤트와 로그를 수집하고 보안 정보 및 이벤트 관리(SIEM) 시스템에 중앙화하며 의심스러운 활동을 경고하는 탐지 규칙을 배포합니다.
1. 대응: 감지가 발생하고 사건을 확인하면 위협을 차단하고 범위를 결정하며 영향을 받은 계정, 자격 증명 및 설정을 해결합니다.

## 보안 텔레메트리 수집 {#collect-security-telemetry}

GitLab이 생성하는 보안 텔레메트리의 종류, 각각이 알려주는 내용 및 제공 서비스와 구독 티어에서 수집할 수 있는 항목을 이해합니다. 감사 이벤트는 조회할 수 있고, 감사 이벤트를 SIEM으로 스트리밍할 수 있으며, 애플리케이션 로그를 수집할 수 있습니다.

자세한 내용은 [보안 텔레메트리](security_telemetry.md)를 참조하세요.

## 보안 사건 감지 {#detect-security-incidents}

GitLab의 보안 관련 활동에 대한 탐지 적용 범위를 구축합니다. 수집할 데이터 소스, SIEM으로 감사 이벤트를 스트리밍하는 방법, 오픈 소스 TLDR 탐지 프레임워크를 사용하는 방법 및 일반적인 사건 시나리오를 모니터링할 신호를 알아봅니다.

자세한 내용은 [보안 사건 탐지](detecting_security_incidents.md)를 참조하세요.

## 보안 사건 대응 {#respond-to-security-incidents}

GitLab의 일반적인 보안 사건을 억제하고 해결합니다. 여기에는 노출된 자격 증명, 손상된 사용자 계정, CI/CD 관련 사건, 손상된 인스턴스 및 잘못 구성된 프로젝트 또는 그룹 설정이 포함됩니다.

자세한 내용은 [보안 사건 대응](responding_to_security_incidents.md)을 참조하세요.

## 관련 항목 {#related-topics}

- [GitLab 보안](_index.md)
- [강화 권장 사항](hardening.md)
- [감사 이벤트 유형](../user/compliance/audit_event_types.md)
