---
stage: AI Clients
group: Developer Clients
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: インタラクティブモードとヘッドレスモードでGitLab Duo CLIを使用します。
title: GitLab Duo CLIを使用する
---

{{< details >}}

- プラン: Premium、Ultimate
- 提供形態: GitLab.com、GitLab Self-Managed、GitLab Dedicated

{{< /details >}}

GitLab Duo CLIは次の2つのモードで使用できます:

- インタラクティブモード: GitLab UIまたはエディタ拡張機能内のGitLab Duo Chatと同様のチャットエクスペリエンスを提供します。ビルドモード、プランモード、自動モードをサポートします。
- ヘッドレスモード: Runner、スクリプト、その他の自動化されたワークフローで非インタラクティブに使用できます。

## 前提条件 {#prerequisites}

- GitLab Duo CLIがインストールされ、[セットアップ](set_up.md)されている。
- [デフォルトのGitLab Duoネームスペース](../profile/preferences.md#namespace-resolution-in-your-local-environment)が設定されているか、GitLab Duoにアクセス権があるプロジェクトを開いている。

## インタラクティブモード {#interactive-mode}

GitLab Duo CLIをインタラクティブモードで使用するには:

1. セットアップに応じて、インタラクティブモードを開始するコマンドを入力します:

   {{< tabs >}}

   {{< tab title="glab" >}}

   ```shell
   glab duo cli
   ```

   {{< /tab >}}

   {{< tab title="duo" >}}

   ```shell
   duo
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. ターミナルウィンドウにプロンプト`>`が表示されます。プロンプトの後に質問またはリクエストを入力し、<kbd>Enter</kbd>を押します。

   例: 

   ```plaintext
   What is this repository about?

   Which issues need my attention?

   Help me implement issue 15.

   The pipelines in MR 23 are failing. Please help me fix them.
   ```

GitLab Duo CLIの処理中にレスポンスをキャンセルするには、<kbd>Escape</kbd>を押します。GitLab Duo CLIは現在の操作を停止し、プロンプトに戻ります。

プロンプトの履歴を表示するには<kbd>↑</kbd>キーを使用します。履歴を検索するには<kbd>Control</kbd>+<kbd>R</kbd>を使用します。

新しいセッションを開始すると、プロンプトのプレースホルダーにGitLab Duo CLIの機能に関するヒントが表示されることがあります。

### 起動カード {#startup-cards}

{{< history >}}

- ウェルカムカードは、GitLab 19.4リリース中のGitLab Duo CLI 9.11.0で[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.11.0)されました。
- `--startup-cards`オプションと`STARTUP_CARDS`環境変数は、GitLab 19.4リリース中のGitLab Duo CLI 9.17.0で[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.17.0)されました。
- オンボーディングカードは、GitLab 19.5リリース中のGitLab Duo CLI 9.28.0で[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.28.0)されました。

{{< /history >}}

インタラクティブモードで新しいセッションを開始すると、ターミナルに起動カードが表示されます。初回の実行時にはオンボーディングカードが、それ以降の実行時にはウェルカムカードが表示されます。既存のセッションを再開する場合、カードは表示されません。

起動カードはデフォルトで有効になっていますが、オフにすることもできます。

#### オンボーディングカード {#onboarding-card}

マシン上でGitLab Duo CLIを初めて実行すると、オンボーディングカードがGitLabマーケットプレイスからの[MCPサーバーの接続](#model-context-protocol-mcp-connections)と[プラグイン](customize.md#plugins)のインストールをサポートします。

このカードには、手順を選択して実行するためのナビゲーションヒントが表示されます。完了した手順には、接続済みのMCPサーバー数またはインストール済みのプラグイン数とともにチェックマークが表示されます。

このカードは、両方の手順を完了した後でも、最初のプロンプトを送信するまで表示され続けます。それ以降の実行では再度表示されません。

#### ウェルカムカード {#welcome-card}

新しいセッションを開始するたびに、デフォルトでウェルカムカードが表示されます。[**セッション開始時に作業アイテムを表示する**](#settings)設定でこのカードをオフにできます。

このカードは一般的なタスクを開始するためのプロンプトを提案し、プロンプトの参照や実行に関するナビゲーションヒントを表示します。たとえば、GitLabプロジェクトで作業している場合、提案されるプロンプトは、オープン中のマージリクエストやイシューから生成されます。それ以外の場合、このカードには一般的な例が表示されます。

マージリクエストの1つに対するプロンプトを選択し、そのソースブランチが存在する場合、プロンプトはGitLab Duoにまずそのブランチをチェックアウトするよう指示します。

[**提案されたプロンプトを/goalセッションとして実行する**](#settings)設定が有効になっていて、インスタンスがGitLab 19.3以降の場合、レビューフィードバックに対応するプロンプトは`/goal`セッションとして実行されます。

#### 起動カードを非表示にする {#hide-the-startup-cards}

起動カードはデフォルトで有効になっています。これらをオフにするには、`--startup-cards`を`false`に設定します:

{{< tabs >}}

{{< tab title="glab" >}}

```shell
glab duo cli --startup-cards false
```

{{< /tab >}}

{{< tab title="duo" >}}

```shell
duo --startup-cards false
```

{{< /tab >}}

{{< /tabs >}}

または、`STARTUP_CARDS`環境変数を`false`に設定します。両方を設定した場合、`--startup-cards`オプションが環境変数よりも優先されます。

### ステータスバー {#status-bar}

画面下部には、次の内容を示すステータスバーが表示されます:

- 現在の作業ディレクトリとGitブランチ。
- 検出されたGitLabプロジェクト、および存在する場合は現在のブランチのオープン中のマージリクエストとそのパイプラインのステータス。
- 実行中の`/goal`セッションの進捗状況。
- 設定済みのMCPサーバーのステータス。

### モードの切り替え {#switch-modes}

インタラクティブモードでは、作業中にGitLab Duo CLIのモードを切り替えることができます:

| モード                 | 権限 | 仕組み                                                                  |
|----------------------|-------------|-------------------------------------------------------------------------------|
| ビルドモード（デフォルト） | 読み取り/書き込み  | GitLab Duoはタスクを実行し、プロジェクトに変更を加えることができます。               |
| プランモード            | 読み取り専用   | GitLab Duoは、変更を加えることなくプロジェクトを分析し、プランを作成できます。 |
| 自動モード            | 読み取り/書き込み  | GitLab Duoは最初に承認を求めることなくツールを使用できます。詳細については、[自動モード](#auto-mode)を参照してください。 |

たとえば、最初にプランモードでGitLab Duoと問題について検討します。準備ができたらビルドモードに切り替え、プランを実装するようにGitLab Duoに指示します。

GitLab Duo CLIでは、現在のモードが`>`プロンプトの下に表示します。モードを切り替えるには、<kbd>Tab</kbd>を押します。

### スラッシュコマンド {#slash-commands}

{{< history >}}

- GitLab 19.0リリース時に、GitLab Duo CLI 8.88.0で`/exit`スラッシュコマンドが[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.88.0)されました。
- GitLab 19.0リリース時に、GitLab Duo CLI 8.94.0で`/doctor`スラッシュコマンドが[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.94.0)されました。
- GitLab 19.0リリース時に、GitLab Duo CLI 8.81.0で`/skills`スラッシュコマンドが[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.81.0)されました。
- GitLab 19.0リリース時に、GitLab Duo CLI 8.95.0で`/mcp`スラッシュコマンドが[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.95.0)されました。
- `/goal`スラッシュコマンドは、GitLab 19.4リリース中のGitLab Duo CLI 9.17.0で[ベータ](../../policy/development_stages_support.md#beta)として[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.17.0)されました。
- `/goal`スラッシュコマンドは、GitLab 19.5リリース中のGitLab Duo CLI 9.27.0で[一般提供](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.27.0)になりました。
- `/compact`スラッシュコマンドは、GitLab 19.2リリース中のGitLab Duo CLI 8.109.0で[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.109.0)されました。
- `/export`スラッシュコマンドは、GitLab 19.4リリース中のGitLab Duo CLI 9.11.0で[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.11.0)されました。
- `/review`スラッシュコマンドは、GitLab 19.4リリース中のGitLab Duo CLI 9.14.0で[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.14.0)されました。
- `/whatsnew`スラッシュコマンドは、GitLab 19.4リリース中のGitLab Duo CLI 9.20.0で[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.20.0)されました。

{{< /history >}}

インタラクティブモードでは、スラッシュコマンドを使用してGitLab Duo CLIを設定したり、アクションを実行したりできます。プロンプトにスラッシュコマンドを入力し、<kbd>Enter</kbd>を押します。

次のスラッシュコマンドを使用できます:

| コマンド     | 説明                                          |
|-------------|------------------------------------------------------|
| `/compact`  | コンテキストスペースを節約するために、会話履歴を圧縮します。 |
| `/copy`     | GitLab Duoの最後のレスポンスをクリップボードにコピーします。  |
| `/doctor`   | GitLab Duo CLI環境の診断情報を表示します。 |
| `/exit`     | GitLab Duo CLIを終了します。                             |
| `/export`   | セッションを移植可能なJSONバンドルとしてエクスポートします。        |
| `/feedback` | バグレポートまたは機能リクエストを送信します。              |
| `/goal`     | 目標の達成に向けて作業するセッションを開始します。GitLab 19.3以降が必要です。 |
| `/help`     | 利用可能なショートカット、モード、スラッシュコマンドを表示します。 |
| `/mcp`      | 設定済みのMCPサーバーとそのステータスを表示します。        |
| `/model`    | 現在のセッションで使用するAIモデルを切り替えます。         |
| `/new`      | 新しいチャットセッションを開始します。                            |
| `/review`   | コードレビューサブエージェントで変更をレビューします。   |
| `/sessions` | セッションを参照、検索、切り替えます。                 |
| `/settings` | 設定パネルを開きます。                             |
| `/skills`   | 現在のプロジェクトで利用可能なAgent Skillsを一覧表示します。  |
| `/whatsnew` | GitLab Duo CLIの最近の変更点を表示します。           |

スラッシュコマンドが開くパネルまたはダイアログを閉じるには、<kbd>Escape</kbd>を押します。

独自のスラッシュコマンドを作成することもできます。詳細については、[カスタムスラッシュコマンド](customize.md#custom-slash-commands)を参照してください。

### 設定 {#settings}

設定を表示および変更するには、インタラクティブモードで`/settings`と入力します。詳細については、[GitLab Duo CLIの設定](settings.md)を参照してください。

### システム通知 {#system-notifications}

{{< history >}}

- GitLab 19.1リリース時に、GitLab Duo CLI 8.105.0でシステム通知が[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.105.0)されました。

{{< /history >}}

ターミナルウィンドウがフォーカスされていないときにセッションでユーザーの確認や対応が必要になると（たとえば、タスクが完了した場合や、ツールの承認が必要な場合）、GitLab Duo CLIはシステム通知を送信できます。

通知は、[設定パネル](settings.md#settings-panel)にある**通知**設定によって制御されます:

- `auto`（デフォルト）: ターミナルがフォーカスされていない場合に、システム通知を送信します。
- `disabled`: システム通知を送信しません。

### ツールの承認 {#tool-approvals}

{{< history >}}

- GitLab 19.0でセッション中にツールを承認するオプションが[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/work_items/2129)されました。
  - [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.80.0) 8.80.0で導入されました。
- GitLab 19.1でパターンベースのツール承認が[導入](https://gitlab.com/groups/gitlab-org/-/work_items/21850)されました。
  - [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.101.0) 8.101.0で導入されました。
- パターンベースのツール承認は、2026年7月10日に[削除](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/merge_requests/3699)されました。
  - [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.3.0) 9.3.0で削除されました。

{{< /history >}}

GitLab Duoがツールを使用する必要がある場合、使用を開始する前に承認を求めるプロンプトが表示されます。たとえば、ファイルを読み取る場合やコマンドを実行する場合などです。

次のオプションがあります:

- **承認**: GitLab Duoはツールを1回使用できます。
- **セッションで承認**: GitLab Duoは、セッションの残りの期間、指定された引数でツールを使用できます。別の引数を使用する場合は、追加の承認が必要です。
- **拒否**: GitLab Duoはツールを使用できません。

> [!note]
> **セッションで承認**オプションを使用するには、管理者がグループまたはインスタンスでこのオプションを有効にする必要があります。詳細については、[ツールの承認](../gitlab_duo_chat/agentic_chat.md#tool-approvals)を参照してください。

### 自動モード {#auto-mode}

{{< details >}}

- プラン: Premium、Ultimate
- 提供形態: GitLab.com、GitLab Self-Managed、GitLab Dedicated

{{< /details >}}

{{< history >}}

- `duo_auto_mode`という名前の[機能フラグ](../../administration/feature_flags/_index.md)を使用して、GitLab 19.5で[導入](https://gitlab.com/gitlab-org/gitlab/-/work_items/618088)されました。デフォルトで有効になっています。
  - [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.22.0) 9.22.0で導入されました。

{{< /history >}}

> [!flag]
> この機能の利用可否は、機能フラグによって制御されます。詳細については、履歴を参照してください。

自動モードでは、GitLab Duoは承認を求めることなくツールを使用します。設定で許可されている場合、GitLab Duoは次のアクションを実行できます:

- ファイルを削除したりシステムを変更したりするコマンドを含む、任意のシェルコマンドを実行します。
- コミットやプッシュを含む、`git`コマンドを実行します。
- イシュー、マージリクエスト、その他のGitLabリソースを作成または更新します。
- MCPツールを実行し、フローを開始します。

自動モードは[エージェントツールガバナンス](../ai-governance/tool-governance.md)を上書きしません。**常に拒否**に設定されたツールはブロックされたままになります。

> [!warning]
> GitLab Duoは間違いを犯すことがあります。GitLab Duoが読み取るファイル、イシュー、マージリクエスト、Webページなどのコンテンツには、プロンプトインジェクションに使用される悪意のある指示が含まれている可能性があります。リスクを抑えるには:
>
> - 信頼できるリポジトリと、破棄できるブランチでのみ自動モードを使用してください。
> - 機密性の高い認証情報を含むデバイスやシェルでは自動モードを使用しないでください。
> - セッションにとどまり、マージする前にすべての変更をレビューしてください。
> - 自動モードが不要な場合は、ビルドモードに戻してください。
>
> 詳細については、[エディタ拡張機能のセキュリティに関する考慮事項](../../editor_extensions/security_considerations.md)を参照してください。

#### 自動モードをオンにする {#turn-on-auto-mode}

**自動モード**設定は、デフォルトでオフになっています。自動モードを使用する前に、インスタンス、グループ、またはプロジェクトでオンにする必要があります。グループはインスタンスから設定を継承し、サブグループとプロジェクトは親グループから設定を継承します。

{{< tabs >}}

{{< tab title="インスタンス" >}}

前提条件: 

- 管理者アクセス権。

インスタンスで自動モードをオンにするには:

1. 右上隅で、**管理者**を選択します。
1. 左側のサイドバーで、**GitLab Duo**を選択します。
1. **設定の変更**を選択します。
1. **自動モード**ドロップダウンリストから、次のいずれかのオプションを選択します:
   - **デフォルトでオン**: 自動モードが使用可能になります。グループとサブグループはこれをオフにできます。
   - **デフォルトでオフ**: 自動モードは使用できません。グループとサブグループはこれをオンにできます。
   - **常にオフ**: 自動モードは使用できません。グループとサブグループはこれをオンにできません。
1. **変更を保存**を選択します。

{{< /tab >}}

{{< tab title="グループ" >}}

前提条件: 

- グループのオーナーロール。

グループで自動モードをオンにするには:

1. 上部のバーで、**検索または移動先**を選択して、グループを見つけます。
1. **設定** > **GitLab Duo**を選択します。
1. **設定の変更**を選択します。
1. **自動モード**ドロップダウンリストから、次のいずれかのオプションを選択します:
   - **デフォルトでオン**: 自動モードが使用可能になります。サブグループとプロジェクトはこれをオフにできます。
   - **デフォルトでオフ**: 自動モードは使用できません。サブグループとプロジェクトはこれをオンにできます。
   - **常にオフ**: 自動モードは使用できません。サブグループとプロジェクトはこれをオンにできません。
1. **変更を保存**を選択します。

{{< /tab >}}

{{< tab title="プロジェクト" >}}

親グループで自動モードが**常にオフ**に設定されている場合、プロジェクトの設定はロックされており、オンにすることはできません。

前提条件: 

- プロジェクトのメンテナーまたはオーナーロールが必要です。

プロジェクトで自動モードをオンにするには:

1. 上部のバーで、**検索または移動先**を選択して、プロジェクトを見つけます。
1. **設定** > **一般**を選択します。
1. **GitLab Duo**を展開します。
1. **自動モード**の切替をオンにします。
1. **変更を保存**を選択します。

{{< /tab >}}

{{< /tabs >}}

#### 自動モードを使用する {#use-auto-mode}

前提条件: 

- GitLab Duo CLI 9.22.0以降。
- プロジェクトで自動モードがオンになっていること。

自動モードを使用するには:

1. プロジェクトでGitLab Duo CLIを起動または再起動して、設定を反映させます。
1. `>`プロンプトの下のモードが`auto`と表示されるまで、<kbd>Tab</kbd>を押します。
1. プロンプトを入力します。自動モードは、そのプロンプト以降に適用されます。

自動モードの使用を停止するには、<kbd>Tab</kbd>を押して別のモードに切り替えます。この変更は次のプロンプトに適用されます。

自動モードはセッション間で保持されません。`/new`で開始したセッションを含め、新規または再開した各セッションは、ビルドモードで開始します。

#### 自動モードのトラブルシューティング {#troubleshooting-auto-mode}

<kbd>Tab</kbd>を押しても`auto`が表示されない場合:

1. プロジェクトで**自動モード**設定がオンになっていることを確認します。
1. 親グループが**常にオフ**に設定されていないことを確認します。
1. GitLab Duo CLIを再起動します。

## ヘッドレスモード {#headless-mode}

> [!caution]
> ヘッドレスモードは、制御された[サンドボックス環境](../../editor_extensions/security_considerations.md#use-development-containers-for-isolation)で注意して使用してください。

非インタラクティブモードでワークフローを実行するには、セットアップに応じたコマンドを使用します:

{{< tabs >}}

{{< tab title="glab" >}}

`glab duo cli run`を使用します: 

```shell
glab duo cli run --goal "Your goal or prompt here"
```

たとえば、ESLintコマンドを実行し、エラーをGitLab Duo CLIに渡して解決させることができます:

```shell
glab duo cli run --goal "Fix these errors: $eslint_output"
```

{{< /tab >}}

{{< tab title="duo" >}}

`duo run`を使用します: 

```shell
duo run --goal "Your goal or prompt here"
```

たとえば、ESLintコマンドを実行し、エラーをGitLab Duo CLIに渡して解決させることができます:

```shell
duo run --goal "Fix these errors: $eslint_output"
```

{{< /tab >}}

{{< /tabs >}}

ヘッドレスモードを使用すると、GitLab Duo CLIは次のように動作します:

- GitLab 19.4以降では、[デベロッパーフロー](../project/merge_requests/developer.md#use-the-flow-in-the-gitlab-duo-cli)を実行します。
- 手動によるツール承認をバイパスし、すべてのツールの使用を自動的に承認します。
- 以前の会話からのコンテキストを保持しません。`run`コマンドを実行するたびに、新しいワークフローが開始されます。

## 画像をコンテキストとして提供する {#provide-images-as-context}

{{< history >}}

- `dap_tool_image_input`という名前の[機能フラグを使用して](../../administration/feature_flags/_index.md)、GitLab 19.5リリース中のGitLab Duo CLI 9.27.0で[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.27.0)されました。デフォルトでは有効になっています。

{{< /history >}}

> [!flag]
> この機能の利用可否は、機能フラグによって制御されます。詳細については、履歴を参照してください。

前提条件: 

- GitLab Duo CLI 9.27.0以降。
- GitLab管理のモデルを使用してください。自分でホストするモデルはサポートされていません。

インタラクティブモードまたはヘッドレスモードでGitLab Duo CLIをローカルで実行すると、GitLab Duoは画像を読み取り、コンテキストとして使用できます。CLIは次のものを読み取れます:

- リポジトリ内の画像ファイル。
- 同じプロジェクト内のイシュー、マージリクエスト、またはコメントに添付された画像。

プロンプト内で直接画像をアップロードすることはできません。代わりに、既存の画像の名前を指定してください:

- リポジトリ内のファイルの場合は、ファイルパスを指定してください。例: `docs/architecture.png`。
- 添付ファイルの場合は、Markdownに表示されるアップロード参照を指定してください。例: `/uploads/<secret>/screenshot.png`。

### イメージの要件 {#image-requirements}

画像をコンテキストとして使用するには、画像が次の要件を満たしている必要があります:

- 形式は、PNG、JPEG、またはWebPファイル
- サイズ: 10 MB以下
- 寸法: 幅または高さが8,000ピクセルを超えないこと

### プロンプトの例 {#example-prompts}

イシューに添付されたスクリーンショットに表示されているUIのバグを修正するよう、GitLab Duo CLIに依頼できます:

```plaintext
Look at the screenshot attached to issue 1234 and fix the alignment bug it shows.
```

アーキテクチャ図を説明するよう、GitLab Duo CLIに依頼できます:

```plaintext
Read docs/architecture.png, explain the data flow, and identify any single points of failure.
```

ホワイトボードの写真を設計ドキュメントに変換するよう、GitLab Duo CLIに依頼できます:

```plaintext
Read whiteboard.jpg and turn it into a design document in docs/design.md.
```

## モデルを選択する {#select-a-model}

{{< history >}}

- GitLab 18.10リリース時に、GitLab Duo CLI 8.68.0で、モデル選択オプションと環境変数が[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.68.0)されました。
- GitLab 18.10リリース時に、GitLab Duo CLI 8.76.0で、モデル選択スラッシュコマンドが[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.76.0)されました。

{{< /history >}}

インタラクティブモードまたはヘッドレスモードで使用するモデルを選択できます。

### インタラクティブモードの場合 {#for-interactive-mode}

選択したモデルはセッション間で保持され、コンテキストを失うことなく、会話の途中でモデルを切り替えることができます。

前提条件: 

- GitLab Duo CLI 8.76.0以降。

インタラクティブモードでモデルを選択するには:

1. インタラクティブモードで`/model`と入力し、<kbd>Enter</kbd>を押します。
1. 矢印キーを使用して利用可能なモデルのリストをスクロールするか、モデル名を入力してリストを絞り込みます。
1. モデルを選択し、<kbd>Enter</kbd>を押してそのモデルに切り替えます。

### ヘッドレスモードの場合 {#for-headless-mode}

選択したモデルはセッション間で保持されません。

前提条件: 

- GitLab Duo CLI 8.68.0以降。

ヘッドレスモードでモデルを選択するには:

1. モデルの[`gitlab_identifier`](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/blob/HEAD/ai_gateway/model_selection/models.yml)を確認します。
1. GitLab Duo CLIを実行するときに、`--model`オプションまたは`GITLAB_DUO_MODEL`環境変数を`gitlab_identifier`の値に設定します。

   {{< tabs >}}

   {{< tab title="glab" >}}

   `--model`オプションを使用します:

   ```shell
   glab duo cli --model <gitlab_identifier_for_the_model>
   ```

   `GITLAB_DUO_MODEL`環境変数を使用します:

   ```shell
   GITLAB_DUO_MODEL=<gitlab_identifier_for_the_model> glab duo cli
   ```

   たとえば、[`GPT-5-Codex - OpenAI`](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/blob/HEAD/ai_gateway/model_selection/models.yml#L448)を使用するには:

   ```shell
   glab duo cli --model gpt_5_codex
   ```

   ```shell
   GITLAB_DUO_MODEL=gpt_5_codex glab duo cli
   ```

   {{< /tab >}}

   {{< tab title="duo" >}}

   `--model`オプションを使用します:

   ```shell
   duo --model <gitlab_identifier_for_the_model>
   ```

   `GITLAB_DUO_MODEL`環境変数を使用します:

   ```shell
   GITLAB_DUO_MODEL=<gitlab_identifier_for_the_model> duo
   ```

   たとえば、[`GPT-5-Codex - OpenAI`](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/blob/HEAD/ai_gateway/model_selection/models.yml#L448)を使用するには:

   ```shell
   duo --model gpt_5_codex
   ```

   ```shell
   GITLAB_DUO_MODEL=gpt_5_codex duo
   ```

   {{< /tab >}}

   {{< /tabs >}}

## セッションを切り替える {#switch-sessions}

GitLab Duo Chatセッションには、会話履歴とワークフローのデータが保存されます。セッションは、GitLab Duo CLI、GitLab UI、およびエディタ拡張機能で共有されます。

たとえば、ブラウザで会話を開始し、ターミナルでその会話を続けることができます。

セッションを参照して切り替えるには:

1. インタラクティブモードで`/sessions`と入力し、<kbd>Enter</kbd>を押します。
1. 矢印キーを使用して利用可能なセッションのリストをスクロールするか、テキストを入力してリストを絞り込みます。
1. セッションを選択し、<kbd>Enter</kbd>を押します。

ヘッドレスモードでセッションを切り替えるには、`--existing-session-id`オプションを使用します。

## Model Context Protocol（MCP）接続 {#model-context-protocol-mcp-connections}

GitLab Duo CLIをローカルまたはリモートのMCPサーバーに接続するには、GitLab IDE拡張機能と同じMCP設定を使用します。手順については、[MCPサーバーを設定する](../gitlab_duo/model_context_protocol/mcp_clients.md#configure-mcp-servers)を参照してください。

## 関連トピック {#related-topics}

- [GitLab Duo CLIの詳細なリファレンス](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/blob/main/packages/cli/app/docs/cli-reference.md)
- [エディタ拡張機能のセキュリティに関する考慮事項](../../editor_extensions/security_considerations.md)
- [GitLab CLI](https://docs.gitlab.com/cli/)
- [GitLab Duo Agent Platformをカスタマイズする](../duo_agent_platform/customize/_index.md)
- [GitLab Duo Agent Platformセッション](../duo_agent_platform/sessions/_index.md)

## トラブルシューティング {#troubleshooting}

GitLab Duo CLIの使用中に、次の問題が発生することがあります。

### 証明書エラー {#certificate-errors}

証明書エラーが発生する可能性があります:

```plaintext
Error: unable to verify the first certificate
Error: self-signed certificate in certificate chain
```

組織でHTTPSインターセプトプロキシなどのためにカスタム認証局（CA）を使用している場合、証明書エラーが発生することがあります。

証明書エラーを解決するには、次のいずれかの方法を使用します:

- システム証明書ストアを使用する（推奨）: 
  1. CA証明書がオペレーティングシステムの証明書ストアにインストールされている場合は、それを使用するようにNode.jsを設定します。これにはNode.js 22.15.0、23.9.0、または24.0.0以降が必要です。
  1. GitLab Duo CLIをコンテナ内で実行する場合は、ホストシステムのストアではなく、コンテナのシステムストアにCA証明書をインストールします。

     ```shell
     export NODE_OPTIONS="--use-system-ca"
     ```

- CA証明書ファイルを指定する: 
  1. 古いバージョンのNode.jsを使用している場合、またはCA証明書がシステムストアにない場合は、Node.jsに証明書ファイルを直接指定します。ファイルはPEM形式である必要があります。
  1. GitLab Duo CLIをコンテナで実行する場合は、コンテナ内の場所を指すパスを設定します。証明書ファイルを提供するには、ボリュームマウントを使用します。

     ```shell
     export NODE_EXTRA_CA_CERTS=/path/to/custom-ca.pem
     ```

### 証明書エラーを無視する {#ignore-certificate-errors}

証明書エラーが引き続き発生する場合は、証明書の検証を無効にできます。

> [!warning]
> 証明書の検証を無効にすることはセキュリティ上のリスクとなります。本番環境で検証を無効にしないでください。

証明書エラーは潜在的なセキュリティ漏洩を警告するものです。そのため、証明書の検証を無効にしても安全であると確信できる場合にのみ、検証を無効にしてください。

前提条件: 

- ブラウザで証明書チェーンを検証した、または管理者がこのエラーを無視しても安全であることを確認した。

証明書の検証を無効にするには:

```shell
export NODE_TLS_REJECT_UNAUTHORIZED=0
```
