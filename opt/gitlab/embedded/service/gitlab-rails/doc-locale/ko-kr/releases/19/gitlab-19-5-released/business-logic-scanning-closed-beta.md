---
title: Business Logic Security Analyzer (폐쇄된 베타)
tier: [ Ultimate ]
offering: [ gitlab_com ]
stage: application_security_testing
documentation_link: "../../../user/application_security/business_logic_scanning/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/632352
categories: [ SAST ]
level: secondary
---

Business Logic Security Analyzer는 코드가 시행하도록 의도된 것을 추론하는 GitLab Duo Agent Platform 기본 플로우입니다. 패턴 기반 스캐너가 놓치기 쉬운 취약성을 찾습니다: 손상된 객체 수준 권한 부여, 누락된 권한 부여 확인 및 대량 할당.

GitLab Duo Chat 또는 API에서 전체 리포지토리 스캔을 시작합니다. 머지 리퀘스트를 자동으로 스캔하려면 Business Logic 스캔 프로필을 프로젝트에 첨부합니다. 결과는 취약성 보고서와 머지 리퀘스트 보안 위젯에 나타납니다.

Business Logic Security Analyzer는 GitLab.com의 GitLab Ultimate 고객을 위한 폐쇄된 베타 버전입니다. 액세스를 요청하려면 담당 계정 팀에 문의하세요. 각 스캔은 GitLab Credits를 소비합니다. 필수 조건 및 설정에 대해서는 [Business logic scanning](../../../user/application_security/business_logic_scanning/_index.md)을 참조하세요.
