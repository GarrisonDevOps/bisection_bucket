---
title: 悪意のあるパッケージを追加するマージリクエストをブロックする
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/policies/merge_request_approval_policies/#block-malicious-packages-with-the-malware-rule"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/19465
categories: [ Security Policy Management ]
level: secondary
---

以前のバージョンのGitLabでは、マージリクエスト承認ポリシーは悪意のあるパッケージを他の脆弱性と同様に扱っていました。検出結果が無視された場合や、ルールの重大度フィルターの範囲外となった場合、害を引き起こすために作られたパッケージであってもマージされる可能性がありました。

今回のリリースで、マージリクエスト承認ポリシーにマルウェアルールを追加できるようになりました。依存関係スキャンがGitLabのマルウェアアドバイザリに記載されているパッケージを検出した場合、検出結果の重大度や状態に関わらず、マージリクエストには承認が必要となります。マルウェアルールは既存のスキャン検出ルールと併用できるため、既存のポリシーを作り直すことなく追加できます。

マルウェアルールを使用するには、プロジェクトで
[SBOMを使用した依存関係スキャン](../../../user/application_security/dependency_scanning/dependency_scanning_sbom/_index.md#turn-on-dependency-scanning)
を実行する必要があります。マルウェアアドバイザリは、npm、PyPI、Maven、Go、NuGet、Cargo、およびRubyGemsパッケージに対応しています。
