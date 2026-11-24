---
title: "Advanced SAST는 Kotlin, Dart 및 Scala 언어를 지원합니다"
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: application_security_testing
documentation_link: ../../../user/application_security/sast/gitlab_advanced_sast/#supported-languages
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23383
categories: [ SAST ]
level: primary
---

Advanced SAST는 이제 Kotlin, Dart 및 Scala 코드베이스를 Java, Python 및 기타 지원되는 언어를 다루는 동일한 심화된 오염 분석으로 스캔하며, 모두 언어별 프론트엔드와 프레임워크 인식 규칙 게이팅을 갖춘 Software Factory 아키텍처를 통해 제공됩니다.

- Kotlin 탐지는 SQL 주입, 안전하지 않은 WebView 사용, OS 명령 주입, 하드코딩된 자격 증명 및 약한 암호화에 대한 Android API를 대상으로 합니다.
- Dart 탐지는 SSRF, 경로 통과, 명령 주입 및 평문 HTTP를 다루는 Flutter 및 Dio 프레임워크 탐지기를 포함합니다.
- Scala 탐지는 SQL 주입, SSRF, 오픈 리디렉트, 경로 통과, 명령 주입 및 XSS에 대한 Play, Slick 및 Akka 프레임워크를 다룹니다.

세 가지 추가 항목 모두 의도적으로 취약한 실제 코드 리포지토리를 사용하여 확인되며, 결과는 소스에서 싱크로의 코드 플로우로 보고됩니다.
