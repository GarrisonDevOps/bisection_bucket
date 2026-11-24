---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Markdownでユーザーがコンテンツを埋め込める埋め込みプロバイダーを選択します。
title: 埋め込まれたコンテンツ
---

{{< details >}}

- プラン: Free、Premium、Ultimate
- 提供形態: GitLab Self-Managed、GitLab Dedicated
- ステータス: 実験的機能

{{< /details >}}

{{< history >}}

- GitLab 18.7で`allow_iframes_in_markdown`[機能フラグ](../feature_flags/_index.md)とともに[導入](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200864)されました。デフォルトでは無効になっています。
- 埋め込みプロバイダーはGitLab 19.5で[導入されました](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254945)。埋め込みプロバイダーは、ドメインの許可リストに代わるものです。GitLab 19.5へのアップグレードにより、既存の許可リストはクリアされます。

{{< /history >}}

> [!flag]
> この機能の利用可否は、機能フラグによって制御されます。詳細については、履歴を参照してください。この機能はテストには利用できますが、本番環境での使用には適していません。

ユーザーは、YouTube動画やFigmaデザインなどの外部プロバイダーからのコンテンツをMarkdownに埋め込むことができます。インスタンスで許可する埋め込みプロバイダーを選択します。利用可能なプロバイダーとそのIDについては、[埋め込まれたコンテンツ](../../user/markdown.md#embedded-content)を参照してください。

GitLabは、利用可能な埋め込みプロバイダーを定義します。各プロバイダーは、受け入れるURL、コンテンツの読み込み元URL、およびそのコンテンツに対するブラウザサンドボックスの制限を定義します。プロバイダーを追加することはできません。

許可されたプロバイダーからのコンテンツは、GitLab内のページ内に読み込まれ、それを表示するユーザーのブラウザでスクリプトを実行できます。信頼できるプロバイダーのみを許可してください。

プロバイダーの許可を停止するか、埋め込みコンテンツをオフにすると、それらのプロバイダーからの既存のコンテンツは元のURLへのリンクとして表示されます。プロバイダーを許可するか、埋め込みコンテンツをオンにしても、誰かが編集したときなど、GitLabが次にレンダリングするまで既存のコンテンツは埋め込まれません。

## 埋め込みプロバイダーを選択する {#choose-embed-providers}

前提条件: 

- 管理者アクセス権。

ユーザーがコンテンツを埋め込める埋め込みプロバイダーを選択するには、次の手順に従います:

1. 右上隅で、{{< ui text="管理者" >}}を選択します。
1. 左側のサイドバーで、{{< ui text="設定" >}} > {{< ui text="一般" >}}を選択します。
1. {{< ui text="埋め込まれたコンテンツ" >}}を展開します。
1. {{< ui text="埋め込みコンテンツを有効にする" >}}チェックボックスを選択します。
1. {{< ui text="埋め込みプロバイダー" >}}で、許可する各プロバイダーのチェックボックスを選択します。
1. {{< ui text="変更を保存" >}}を選択します。

`iframe_rendering_enabled`属性と`iframe_rendering_allowlist`属性を使用して、[アプリケーション設定API](../../api/settings.md#available-settings)で埋め込みプロバイダーを選択することもできます。
