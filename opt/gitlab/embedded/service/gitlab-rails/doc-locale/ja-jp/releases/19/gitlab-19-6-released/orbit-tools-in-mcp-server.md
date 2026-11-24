---
title: GitLab MCPサーバーのOrbitツール
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: analytics
documentation_link: "../../../user/model_context_protocol/mcp_server/#select-tool-groups-toolsets"
work_item: https://gitlab.com/gitlab-org/orbit/knowledge-graph/-/work_items/1294
categories: [ Orbit ]
level: secondary
weight: 50
---

以前のバージョンのGitLabでは、GitLab OrbitにクエリするためにAIエージェントが別のMCPサーバー接続を必要としていました。
今回のリリースで、GitLab MCPサーバーに[Orbitツールセット](../../../user/model_context_protocol/mcp_server.md#select-tool-groups-toolsets)を追加できるようになり、エージェントはすでに使用している接続からOrbitのコンテキストを取得できます。
