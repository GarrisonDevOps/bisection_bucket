---
title: "IDEのDeveloper FlowとAgentic Chatで画像をコンテキストとして使用"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/project/merge_requests/developer/#provide-images-as-context"
work_item: https://gitlab.com/groups/gitlab-org/modelops/applied-ml/code-suggestions/-/work_items/61
categories: [ Duo Developer ]
level: secondary
weight: 50
---

以前のバージョンのGitLabでは、Developer FlowとAgentic Chatはテキストのみを読み取ることができたため、バグレポートのスクリーンショットやデザインディスカッションの図はモデルに渡されませんでした。今回のリリースで、Developer Flow（Agentic Chatから起動した場合を含む）およびIDEのAgentic Chatが、同じプロジェクト内のリポジトリの画像やイシュー、マージリクエスト、コメントの添付ファイルを読み取り、コンテキストとして使用できるようになりました。

プロンプトに直接画像をアップロードすることはできません。代わりに、リポジトリ内のファイルパスまたはアップロード参照を使用して、既存の画像を指定してください。詳細はドキュメントをご参照ください。
