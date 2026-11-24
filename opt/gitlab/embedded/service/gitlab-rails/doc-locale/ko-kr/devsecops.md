---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab을 사용하고 관리하는 방법을 알아보세요. GitLab은 소프트웨어 개발을 위한 가장 확장 가능한 Git 기반의 완전히 통합된 플랫폼입니다.
title: 'GitLab: DevSecOps 플랫폼'
---

DevSecOps는 개발, 보안, 운영의 조합입니다. 개발 수명 주기 전체에서 보안을 통합하는 소프트웨어 개발 접근 방식입니다.

## DevSecOps와 DevOps 비교 {#devsecops-compared-to-devops}

DevOps는 개발과 운영을 결합하여 소프트웨어 개발 및 배포의 효율성, 속도 및 보안을 향상시킵니다.

DevOps는 안전한 소프트웨어를 최고의 속도로 구상하고, 구축하고, 제공하기 위해 함께 일하는 것을 의미합니다. DevOps 사례에는 자동화, 협업, 빠른 피드백 및 반복적 개선이 포함됩니다.

DevSecOps는 DevOps의 진화입니다. DevSecOps는 소프트웨어 개발의 모든 단계에서 애플리케이션 보안 사례를 포함합니다.

개발 프로세스 전체에서 도구와 방법을 사용하여 라이브 애플리케이션을 보호하고 모니터링합니다. 컨테이너 및 오케스트레이터와 같은 새로운 공격 표면도 모니터링하고 보호해야 합니다. DevSecOps 도구는 보안 워크플로우를 자동화하여 개발 및 보안 팀을 위한 적응 가능한 프로세스를 만들고, 협업을 개선하고 사일로를 없앱니다. 보안을 소프트웨어 개발 수명 주기에 포함시킴으로써, 빠르게 움직이는 반복적 프로세스를 지속적으로 보호하고 품질을 희생하지 않으면서 효율성을 개선할 수 있습니다.

## DevSecOps 기본 사항 {#devsecops-fundamentals}

DevSecOps 기본 사항은 다음을 포함합니다:

- 자동화
- 협업
- 정책 가드레일
- 가시성

자세한 내용은 [DevSecOps에 관한 이 문서](https://about.gitlab.com/topics/devsecops/)를 참조하세요.

## DevSecOps 실제 사용 {#devsecops-in-practice}

다음 GitLab 기능은 모두 견고한 DevSecOps 플랫폼의 일부입니다:

- 좌측 이동 보안: 정적 애플리케이션 보안 테스트(SAST) 및 머지 리퀘스트의 종속성 검사는 코드 병합 전에 취약성을 감지합니다.
- 컨테이너 보안: CVE용 이미지 스캔, 런타임 보호 및 Kubernetes 보안 정책은 최소 권한 액세스를 적용합니다.
- 코드 기반 인프라(IaC) 스캔: Terraform, CloudFormation 및 Kubernetes 매니페스트의 잘못된 구성 자동 감지입니다.
- 시크릿 검색: 사전 커밋 훅 및 CI/CD 파이프라인 스캔은 리포지토리의 자격 증명 누출을 방지합니다.
- 보안 대시보드: CVSS 점수, 악용 가능성 메트릭 및 수정 워크플로우를 사용한 중앙 집중식 취약성 추적입니다.

## DevSecOps가 당신에게 적합한가? {#is-devsecops-right-for-you}

조직이 다음 과제 중 하나에 직면해 있다면 DevSecOps 접근 방식이 당신에게 적합할 수 있습니다.

<!-- Do not delete the double spaces at the end of these lines. They improve the rendered view. -->

- 개발, 보안 및 운영 팀이 분리되어 있습니다. 개발과 운영이 보안 문제로부터 분리되어 있으면 안전한 소프트웨어를 구축할 수 없습니다. 또한 보안 팀이 개발 프로세스의 일부가 아니면 위험을 사전에 파악할 수 없습니다. DevSecOps는 팀을 함께 모아 워크플로우를 개선하고 아이디어를 공유합니다. 조직은 직원 사기와 유지 시간이 개선되는 것을 볼 수도 있습니다.

- 긴 개발 주기로 인해 고객 또는 이해관계자의 요구를 충족하기가 어려워지고 있습니다. 어려움의 한 가지 이유는 보안일 수 있습니다. DevSecOps는 개발 수명 주기의 모든 단계에서 보안을 구현하므로, 견고한 보안은 전체 프로세스가 중단될 필요가 없습니다.

- 클라우드로 마이그레이션하고 있습니다(또는 검토 중입니다). 클라우드로 이동하면 새로운 개발 프로세스, 도구 및 시스템을 도입해야 하는 경우가 많습니다. 프로세스를 더 빠르고 안전하게 만들 수 있는 좋은 기회이며, DevSecOps를 사용하면 훨씬 쉬워질 수 있습니다.

DevSecOps를 시작하려면 [더 알아보고 GitLab Ultimate을 무료로 시도하세요](https://about.gitlab.com/solutions/application-security-testing/).
