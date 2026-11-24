---
title: AIエージェント向けGitLab MCPサーバーツールのガバナンス
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: software_supply_chain_security
documentation_link: "../../../user/ai-governance/tool-governance/#gitlab-mcp-server-tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/633490
categories: [ AI Governance ]
level: primary
weight: 50
---

AIエージェントが使用できるGitLab MCPサーバーツールを制御できるようになりました。設定したルールは、接続するすべてのクライアントにGitLabが適用します。

トップレベルグループのオーナーは、各ツールに次のいずれかを設定できます。

- **常に拒否**: ツールは完全にブロックされ、エージェントからは見えません。
- **常に確認**: ツールを実行する前に、ユーザーの承認が必要です。
- **常に許可**: ツールは通常どおり実行されます。

この機能はベータ版です。フィードバックは[イシュー633490](https://gitlab.com/gitlab-org/gitlab/-/work_items/633490)をご覧ください。
