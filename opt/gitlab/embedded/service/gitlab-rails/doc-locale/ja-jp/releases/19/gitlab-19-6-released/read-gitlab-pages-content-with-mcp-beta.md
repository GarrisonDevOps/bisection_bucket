---
title: MCPサーバーでGitLab Pagesのコンテンツを読み取る
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools/#get_pages_content"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/617718
categories: [ Agent Tools ]
co_create: true
weight: 50
---

以前のバージョンのGitLabでは、GitLab MCPサーバーでPagesサイトのソースを読み取ることができましたが、パイプラインによってビルドされたサイト自体は読み取れませんでした。`get_pages_content`ツールを使用することで、GitLab MCPサーバーは指定したPages URLの公開コンテンツを読み取れるようになりました。閲覧権限を持つプライベートPagesサイトも対象となります。

このコントリビュートをいただいた[Mawueli](https://gitlab.com/mawueli)さんに感謝します！
