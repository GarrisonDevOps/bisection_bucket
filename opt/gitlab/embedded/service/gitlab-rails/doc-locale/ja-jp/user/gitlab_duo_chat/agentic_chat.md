---
stage: AI Clients
group: Duo Chat
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab Duo Agentic Chatを使用して、複雑な質問に回答し、ファイルを自律的に作成または編集できます。
title: GitLab Duo Agentic Chat
---

{{< details >}}

- プラン: [Free](../../subscriptions/gitlab_credits.md#for-the-free-tier)、Premium、Ultimate
- 提供形態: GitLab.com、GitLab Self-Managed、GitLab Dedicated、GitLab Dedicated for Government

{{< /details >}}

{{< collapsible title="モデル情報" >}}

- [デフォルトLLM](../duo_agent_platform/model_selection.md#default-models)
- [セルフホストモデル対応のGitLab Duo](../../administration/gitlab_duo_self_hosted/_index.md)で利用可能

{{< /collapsible >}}

{{< history >}}

- VS Codeは、[実験的機能](../../policy/development_stages_support.md)として`duo_agentic_chat`[フラグ](../../administration/feature_flags/_index.md)とともに、GitLab 18.1の[GitLab.comで導入](https://gitlab.com/gitlab-org/gitlab/-/work_items/540917)されました。デフォルトでは無効になっています。
- VS Codeは、GitLab 18.2の[GitLab Self-Managedで有効](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/196688)になりました。
- GitLab UIは、`duo_workflow_workhorse`および`duo_workflow_web_chat_mutation_tools`[機能フラグ](../../administration/feature_flags/_index.md)とともに、GitLab 18.2の[GitLab.comとGitLab Self-Managedで導入](https://gitlab.com/gitlab-org/gitlab/-/issues/546140)されました。どちらのフラグもデフォルトで有効になっています。
- 機能フラグ`duo_agentic_chat`は、GitLab 18.2でデフォルトで有効になっています。
- JetBrains IDEがGitLab 18.2で[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/issues/1077)されました。
- GitLab 18.2でベータ版に変更されました。
- Visual Studio for WindowsがGitLab 18.3で[導入](https://gitlab.com/gitlab-org/editor-extensions/gitlab-visual-studio-extension/-/issues/245)されました。
- GitLab 18.3でGitLab Duo Coreに[追加](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/201721)されました。
- 機能フラグ`duo_workflow_workhorse`および`duo_workflow_web_chat_mutation_tools`は、GitLab 18.4で[削除](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/198487)されました。
- GitLab Self-Managed上のGitLab Duo Agent Platform（[セルフホストモデル](../../administration/gitlab_duo_self_hosted/_index.md)とクラウド接続されたGitLabモデルの両方）が、GitLab 18.4で`self_hosted_agent_platform`[機能フラグ](../../administration/feature_flags/_index.md)とともに[実験的機能](../../policy/development_stages_support.md#experiment)として[導入](https://gitlab.com/groups/gitlab-org/-/work_items/19213)されました。デフォルトでは無効になっています。
- GitLab 18.5でGitLab Self-Managed上のGitLab Duo Agent Platformは実験的機能から[ベータ版](https://gitlab.com/groups/gitlab-org/-/epics/19402)に変更されました。
- GitLab 18.6で[デフォルトLLMが更新](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/issues/1541)され、Claude Sonnet 4.5になりました。
- GitLab 18.7で機能フラグ`self_hosted_agent_platform`が[有効](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/208951)になりました。
- GitLab 18.7で[デフォルトLLMが更新](https://gitlab.com/groups/gitlab-org/-/epics/19998)され、Claude Haiku 4.5になりました。
- GitLab 18.8で`agentic_chat_ga`および`ai_duo_agent_platform_ga_rollout_self_managed`[フラグ](../../administration/feature_flags/_index.md)とともに[一般提供](https://gitlab.com/gitlab-org/gitlab/-/issues/581872)になりました。どちらのフラグもデフォルトで有効になっています。機能フラグ`duo_agentic_chat`は削除されました。
- 機能フラグ[`self_hosted_agent_platform`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/218589)、[`agentic_chat_ga`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/219679)、[`ai_duo_agent_platform_ga_rollout_self_managed`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/219679)はGitLab 18.10で削除されました。
- GitLab 18.10で、GitLab.comのFreeプランにおいてGitLabクレジットを使用して利用できるようになりました。

{{< /history >}}

GitLab Duo Agentic Chatは、GitLab Duo Non-Agentic Chatの拡張バージョンです。この新しいChatは、複雑な質問に対しより包括的に回答できるよう、ユーザーに代わって自律的にアクションを実行できます。

非エージェント型Chatが単一のコンテキストに基づいて質問に回答するのに対し、エージェント型Chatは、GitLabプロジェクト全体の複数のソースから情報を検索、取得、統合することで、より徹底的で関連性の高い回答を提供します。

Agentic Chatは次のことが可能です:

- キーワードに基づく検索を使用して、プロジェクト内の関連するイシュー、マージリクエスト、その他のアーティファクトを検索する（セマンティック検索ではありません）。
- ファイルパスを手動で指定しなくても、ローカルプロジェクト内のファイルにアクセスする。
- 複数の場所でファイルを作成および編集する。
- イシュー、マージリクエスト、CI/CDパイプラインなどのリソースを取得する。
- 複数のソースを分析して、完全な回答を提供する。[Model Context Protocol](../gitlab_duo/model_context_protocol/_index.md)を使用して、外部データソースおよびツールに接続する。
- カスタマイズされたルールを使用して、カスタマイズされた回答を提供する。
- GitLab UIでChatの使用時に、コミットを作成する。

<i class="fa-youtube-play" aria-hidden="true"></i> 概要については、[GitLab Duo Chat（エージェント型）](https://youtu.be/uG9-QLAJrrg?si=c25SR7DoRAep7jvQ)を参照してください。

<!-- Video published on 2025-06-02 -->

フィードバックは[イシュー542198](https://gitlab.com/gitlab-org/gitlab/-/issues/542198)で共有してください。

## GitLab Duo Chatを使用する {#use-gitlab-duo-chat}

GitLab Duo Chatは、以下で使用できます:

- GitLab UI。
- VS Code。
- JetBrains IDE。
- Visual Studio for Windows。

[GitLab Duo CLI](../gitlab_duo_cli/_index.md)を使用すると、Agentic Chatをターミナルで使うこともできます。

### GitLab UIでGitLab Duo Chatを使用する {#use-gitlab-duo-chat-in-the-gitlab-ui}

{{< history >}}

- GitLab 18.4でChatが最新の会話を記憶する機能が[追加](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203653)されました。
- GitLab 18.6でGitLab.comに新しいナビゲーションとGitLab Duoサイドバーが`paneled_view`[フラグ](../../administration/feature_flags/_index.md)とともに導入されました。デフォルトでは有効になっています。
- 以前のナビゲーション手順はGitLab 18.7で削除されました。
- GitLab 18.8で新しいナビゲーションとGitLab Duoサイドバーが[一般提供](https://gitlab.com/gitlab-org/gitlab/-/work_items/574049)になりました。機能フラグ`paneled_view`は削除されました。
- 前の質問を再試行する機能は、GitLab 19.5で`agentic_manual_retry_for_duo_chat_responses`という名前の[フラグ](../../administration/feature_flags/_index.md)を使用して[導入](https://gitlab.com/groups/gitlab-org/-/work_items/21289)されました。デフォルトでは無効になっています。
- 前の質問を再試行する機能は、GitLab 19.5で[一般提供](https://gitlab.com/gitlab-org/gitlab/-/work_items/601522)されました。機能フラグ`agentic_manual_retry_for_duo_chat_responses`は削除されました。

{{< /history >}}

前提条件: 

- [GitLab Duo Agent Platformの前提条件](../duo_agent_platform/_index.md#prerequisites)を満たしている。
- [デフォルトのGitLab Duoネームスペース](../profile/preferences.md#set-a-default-gitlab-duo-namespace)を設定している。

GitLab UIでChatを使用するには:

1. 上部のバーで、**検索または移動先**を選択して、プロジェクトを見つけます。
1. GitLab Duoサイドバーで、**新しいチャットを追加**（{{< icon name="pencil-square" >}}）または**現在のGitLab Duo Chat**（{{< icon name="duo-chat" >}}）のいずれかを選択します。

   新しいチャットを選択した場合は、ドロップダウンリストからエージェントを選択します。

   画面右側のGitLab Duoサイドバーに、Chatの会話が表示されます。

1. チャットテキストボックスの下で、**エージェント**切替がオンになっていることを確認します。
1. チャットテキストボックスに質問を入力し、<kbd>Enter</kbd>キーを押すか、**送信**を選択します。
   - チャットに[コンテキスト](../duo_agent_platform/context.md#gitlab-duo-agentic-chat)を追加できます。
   - インタラクティブなAIチャットが回答を生成するまで、数秒かかる場合があります。
1. オプション。次のことが可能です。
   - **再試行**（{{< icon name="retry" >}}）を選択すると、質問に対する別の回答を取得できます。矢印を使用して、元の回答または再試行の回答を選択し、会話を続けます。
   - フォローアップの質問をする。
   - [別の会話](#have-multiple-conversations)を開始する。

Webページをリロードしたり別のWebページに移動したりしても、Chatは最新の会話を記憶し、その会話はChatドロワーでアクティブなままです。

#### 基本フロー {#foundational-flows}

{{< history >}}

- GitLab 19.2で、GitLab Duo Agentic Chatの会話において基本フローをトリガーする機能が`agentic_foundational_flow_tool`[機能フラグ](../../administration/feature_flags/_index.md)とともに[導入](https://gitlab.com/groups/gitlab-org/-/work_items/20484)されました。デフォルトでは有効になっています。
- GitLab 19.5で[一般提供](https://gitlab.com/gitlab-org/gitlab/-/work_items/605446)になりました。機能フラグ`agentic_foundational_flow_tool`は削除されました。

{{< /history >}}

必要に応じて、次の基本フローをAgentic Chatの会話からトリガーして、質問に答えたり目標を達成したりできます。

- [デベロッパーフロー](../project/merge_requests/developer.md#use-the-flow-in-agentic-chat)
- [コードレビューフロー](../duo_agent_platform/flows/foundational_flows/code_review/_index.md#use-the-flow)
- [CI/CDパイプライン修正フロー](../../ci/pipelines/fix_pipeline.md#fix-the-pipeline-in-a-merge-request)

#### スラッシュコマンドでフローをトリガーする {#trigger-a-flow-with-a-slash-command}

{{< history >}}

- GitLab 19.4で`duo_chat_flow_commands`[機能フラグ](../../administration/feature_flags/_index.md)とともに[導入](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252920)されました。デフォルトでは無効になっています。
- GitLab 19.4で[GitLab.comで有効化](https://gitlab.com/gitlab-org/gitlab/-/work_items/629298)されました。
- GitLab 19.5で[一般提供](https://gitlab.com/gitlab-org/gitlab/-/work_items/629298)になりました。

{{< /history >}}

GitLab Duo Agentic Chatでは、スラッシュコマンドでフローを開始できます。フローにトリガーが設定されていない場合や、トリガーを待たずに自分でフローを開始したい場合に、フローコマンドを使用します。

前提条件: 

- プロジェクトでチャットを開いている必要があります。フローコマンドはプロジェクト外では使用できません。
- フローは[プロジェクトで有効化](../duo_agent_platform/flows/custom.md#enable-a-flow)されている必要があります。

> [!warning]
> スラッシュコマンドでフローをトリガーすると、そのフローはGitLab APIおよびGitへの書き込みアクセス権を持ちます。フローは変更をコミットおよびプッシュしたり、イシューやマージリクエストにコメントを投稿したりできます。チャットとは異なり、フローはこれらのアクションを承認するようユーザーに求めません。[ツール承認](#tool-approvals)は、チャットセッションにのみ適用され、そのセッションが開始するフローには適用されません。GitLab UIから開始されたフローはCI/CDパイプラインとして実行されるため、各フローの実行でも[コンピューティング時間](../../ci/pipelines/compute_minutes.md)が使用されます。

チャットからフローをトリガーするには:

1. 上部のバーで、**検索または移動先**を選択して、プロジェクトを見つけます。
1. GitLab Duoサイドバーで、新規または既存のチャットの会話を開きます。
1. チャットメッセージボックスで、メッセージの先頭に`/`を入力します。
1. **フロー**セクションで、フローを選択します。コマンドは、slug形式のフロー名に`/flow:`プレフィックスを付けたものです。たとえば、`Security scanner`という名前のフローは`/flow:security-scanner`になります。プロジェクト内の2つのフローが同じコマンドを生成する名前を持つ場合、2つ目のコマンドには数値IDが追加されます。
1. オプション。コマンドの後に、フローのゴールを入力します。例: `/flow:security-scanner check the auth module`。
1. <kbd>Enter</kbd>キーを押すか、**送信**を選択します。

#### `/goal`コマンドで長時間実行タスクを開始する {#start-a-long-running-task-with-the-goal-command}

{{< history >}}

- GitLab 19.5で`duo_chat_goal_command`[機能フラグ](../../administration/feature_flags/_index.md)とともに[導入](https://gitlab.com/groups/gitlab-org/-/work_items/23107)されました。デフォルトでは無効になっています。
- GitLab 19.5で[GitLab.comで有効化](https://gitlab.com/groups/gitlab-org/-/work_items/23107)されました。

{{< /history >}}

> [!flag]
> この機能の利用可否は、機能フラグによって制御されます。詳細については、履歴を参照してください。

一度に1ターンずつ回答し、続行を依頼するのを待つのではなく、GitLab Duoにタスクが完了するまで作業を続けさせたい場合は、`/goal`を使用します。

ゴールを送信すると、チャットはそのゴールに向けて作業する[デベロッパーフロー](../project/merge_requests/developer.md)セッションを開始します。ゴールは、失敗しているテストの一式を修正する、または複数のファイルにまたがる変更を行うなど、明確な終了状態を持つ具体的な変更に最も適しています。質問をする場合は、代わりに通常のチャットメッセージを使用してください。

前提条件: 

- プロジェクトで[チャットウィンドウを開き](#use-gitlab-duo-chat-in-the-gitlab-ui)ます。`/goal`はプロジェクト外では使用できません。
- トップレベルグループでデベロッパーフローを有効にすることを含め、[デベロッパーフローの前提条件](../project/merge_requests/developer.md#prerequisites)を満たしてください。

> [!warning]
> ゴールはデベロッパーフローを実行し、これはGitLab APIおよびGitへの書き込みアクセス権を持ちます。フローは変更をコミットおよびプッシュしたり、マージリクエストを作成したり、イシューやマージリクエストにコメントを投稿したりできます。チャットとは異なり、フローはこれらのアクションを承認するようユーザーに求めません。[ツール承認](#tool-approvals)は、チャットセッションにのみ適用され、そのセッションが開始するフローには適用されません。GitLab UIから開始されたフローはCI/CDパイプラインとして実行されるため、各ゴールでも[コンピューティング時間](../../ci/pipelines/compute_minutes.md)が使用されます。

長時間実行タスクを開始するには:

1. 上部のバーで、**検索または移動先**を選択して、プロジェクトを見つけます。
1. GitLab Duoサイドバーで、新規または既存のチャットの会話を開きます。
1. チャットメッセージボックスで、次のいずれかを行います:
   - メッセージの先頭に`/goal`を入力し、リストから選択します。
   - **その他の操作**（{{< icon name="plus" >}}）> **ゴール**を選択します。

   メッセージボックスに**ゴール**ラベルが表示されます。
1. 実行してほしい内容を記述します。例: 

   ```plaintext
   Fix the failing tests in spec/models/user_spec.rb
   ```

1. <kbd>Enter</kbd>キーを押すか、**送信**を選択します。

会話内で、メッセージに**ゴール**ラベルが表示されます。

メッセージを送信する前にゴールを削除するには、**ゴール**ラベルで**ゴールを削除**（{{< icon name="close" >}}）を選択します。

### VS CodeでGitLab Duo Chatを使用する {#use-gitlab-duo-chat-in-vs-code}

前提条件: 

- [GitLab for VS Code拡張機能バージョン6.15.1以降をインストールして設定](../../editor_extensions/visual_studio_code/setup.md)している。
- [GitLab Duo Agent Platformの前提条件](../duo_agent_platform/_index.md#prerequisites)を満たしている。
- [デフォルトのGitLab Duoネームスペース](../profile/preferences.md#set-a-default-gitlab-duo-namespace)を設定している。

GitLab Duo Chatをオンにする: 

1. VS Codeで、設定エディタを開きます:
   - macOSでは、<kbd>Command</kbd>+<kbd>,</kbd>を押します。
   - WindowsまたはLinuxでは、<kbd>Control</kbd>+<kbd>,</kbd>を押します。
1. **Extensions** > **GitLab** > **GitLab Duo**を選択します。
1. **GitLab › Duo Agent Platform: Enabled**で、**Enable GitLab Duo Agent Platform**チェックボックスをオンにします。

その後、GitLab Duo Chatを使用するには:

1. 左側のサイドバーで、**GitLab Duo Agent Platform**（{{< icon name="duo-agentic-chat" >}}）を選択します。
1. [クラシックレイアウト](#change-the-layout-in-your-ide)を使用している場合は、**チャット**タブを選択します。
1. プロンプトが表示されたら、**Refresh page**を選択します。
1. メッセージボックスに質問を入力し、<kbd>Enter</kbd>キーを押すか、**送信**を選択します。

### JetBrains IDEでGitLab Duo Chatを使用する {#use-gitlab-duo-chat-in-jetbrains-ides}

前提条件: 

- バージョン3.11.1以降の[JetBrains IDE用GitLab Duoプラグインをインストールして設定](../../editor_extensions/jetbrains_ide/setup.md)します。
- [GitLab Duo Agent Platformの前提条件](../duo_agent_platform/_index.md#prerequisites)を満たしている。
- [デフォルトのGitLab Duoネームスペース](../profile/preferences.md#set-a-default-gitlab-duo-namespace)を設定している。

GitLab Duo Chatをオンにする: 

1. JetBrains IDEで、**Settings** > **Tools** > **GitLab Duo**に移動します。
1. **GitLab Duo Agent Platform**で、**Enable GitLab Duo Agent Platform**チェックボックスを選択します。
1. プロンプトが表示されたら、IDEを再起動します。

その後、GitLab Duo Chatを使用するには:

1. 右側のツールウィンドウバーで、**GitLab Duo Agent Platform**（{{< icon name="duo-agentic-chat" >}}）を選択します。
1. [クラシックレイアウト](#change-the-layout-in-your-ide)を使用している場合は、**チャット**タブを選択します。
1. メッセージボックスに質問を入力し、<kbd>Enter</kbd>キーを押すか、**送信**を選択します。

### Visual StudioでGitLab Duo Chatを使用する {#use-gitlab-duo-chat-in-visual-studio}

前提条件: 

- [GitLab for Visual Studio拡張機能](../../editor_extensions/visual_studio/setup.md)バージョン0.60.0以降をインストールして設定している。
- [GitLab Duo Agent Platformの前提条件](../duo_agent_platform/_index.md#prerequisites)を満たしている。
- [デフォルトのGitLab Duoネームスペース](../profile/preferences.md#set-a-default-gitlab-duo-namespace)を設定している。

GitLab Duo Chatをオンにする: 

1. Visual Studioで、**Tools** > **Options** > **GitLab**に移動します。
1. **GitLab**で、**General**を選択します。
1. **Enable Agentic Duo Chat**で、**True**を選択し、**OK**を選択します。

その後、GitLab Duo Chatを使用するには:

1. **Extensions** > **GitLab** > **Open Agentic Chat**を選択します。
1. メッセージボックスに質問を入力し、**Enter**キーを押します。

## IDEでレイアウトを変更する {#change-the-layout-in-your-ide}

{{< history >}}

- 新しいレイアウトは、GitLab for VS Code 7.2.0およびJetBrains IDE向けGitLab Duoプラグイン3.50.0で[デフォルトになりました](https://gitlab.com/groups/gitlab-org/editor-extensions/-/epics/243)。

{{< /history >}}

VS CodeおよびJetBrains IDEでは、**GitLab Duo Agent Platform**パネルはデフォルトで新しいレイアウトを使用します。新しいレイアウトにはタブがありません。会話の開始、チャット履歴の表示、エージェントとモデルの選択を同じビューで行います。

クラシックレイアウトには、個別の**チャット**タブと**フロー**タブがあります。クラシックレイアウトに切り替えると、次のことができます:

- [ソフトウェア開発フロー](../../editor_extensions/software_development.md)を使用します。
- IDEで実行したフローを表示します。

IDEは選択したレイアウトを記憶します。Visual Studioはクラシックレイアウトのみを使用します。

### クラシックレイアウトに切り替える {#switch-to-the-classic-layout}

レイアウトが変更される前に、切り替える理由を尋ねる任意のアンケートが表示されます。次のことが可能です。

- 理由を1つ以上選択し、**フィードバックを共有**を選択します。
- 回答せずに切り替えるには、**次回から表示しない**を選択します。
- 回答せずに切り替えるには、**やめる**（{{< icon name="close" >}}）を選択します。次回切り替える際に、アンケートが再度表示されます。

フィードバックを共有するか**次回から表示しない**を選択すると、アンケートは再度表示されません。

{{< tabs >}}

{{< tab title="VS Code" >}}

クラシックレイアウトに切り替えるには:

1. サイドバーで、**GitLab Duo Agent Platform**（{{< icon name="duo-agentic-chat" >}}）を選択します。
1. パネルのタイトルバーで、**クラシックレイアウトを使用**を選択します。
1. オプション。必要に応じて、アンケートに回答します。

{{< /tab >}}

{{< tab title="JetBrains IDE" >}}

クラシックレイアウトに切り替えるには:

1. ツールウィンドウバーで、**GitLab Duo Agent Platform**（{{< icon name="duo-agentic-chat" >}}）を選択します。
1. ツールウィンドウのタイトルバーで、**クラシックレイアウトを使用**を選択します。
1. オプション。必要に応じて、アンケートに回答します。

設定からも切り替えることができます。**設定** > **ツール** > **GitLab Duo**に移動し、**GitLab Duo Agent Platform**の下にある**クラシックレイアウトを使用**チェックボックスを選択します。

{{< /tab >}}

{{< /tabs >}}

### 新しいレイアウトに切り替える {#switch-to-the-new-layout}

新しいレイアウトに戻すには:

- VS Codeでは、**GitLab Duo Agent Platform**パネルのタイトルバーで**新しいレイアウトを使用**を選択します。
- JetBrains IDEでは、**GitLab Duo Agent Platform**ツールウィンドウのタイトルバーで**新しいレイアウトを使用**を選択します。**設定** > **ツール** > **GitLab Duo**に移動し、**GitLab Duo Agent Platform**の下にある**クラシックレイアウトを使用**チェックボックスをオフにすることもできます。

## チャット履歴を表示する {#view-the-chat-history}

{{< history >}}

- Chat履歴がGitLab 18.2のIDEに[導入](https://gitlab.com/groups/gitlab-org/-/epics/17922)されました。
- GitLab 18.3でGitLab UIに[追加](https://gitlab.com/gitlab-org/gitlab/-/issues/556875)されました。

{{< /history >}}

チャット履歴を表示するには:

- GitLab UIのGitLab Duoサイドバーで、**GitLab Duo Chat履歴**（{{< icon name="history" >}}）を選択します。

- IDEでは、パネル上部で**履歴**（{{< icon name="history" >}}）を選択します。[クラシックレイアウト](#change-the-layout-in-your-ide)では、メッセージボックスの右上隅にある**チャット履歴**（{{< icon name="history" >}}）を選択します。

GitLab UIでは、チャット履歴内のすべての会話が表示されます。

IDEでは、チャット履歴を下にスクロールすると、古い会話が読み込まれます。クラシックレイアウトでは、直近20件の会話のみが表示されます。

## 複数の会話を行う {#have-multiple-conversations}

{{< history >}}

- 複数の会話機能がGitLab 18.3で[導入](https://gitlab.com/gitlab-org/gitlab/-/issues/556875)されました。
- GitLab UIでチャット履歴を検索する機能がGitLab 18.9で[導入](https://gitlab.com/gitlab-org/gitlab/-/work_items/582513)されました。

{{< /history >}}

GitLab Duo Chatと無制限の数の同時会話を行うことができます。

会話は、GitLab UIのGitLab Duo ChatとIDE間で同期されます。

1. GitLab UIまたはIDEでGitLab Duo Chatを開きます。
1. 質問を入力し、<kbd>Enter</kbd>キーを押すか、**送信**を選択します。
1. 新しいChatの会話を作成します:
   - GitLab UIでは、次のいずれかを実行できます:
     - 特定のエージェントとの新しい会話を作成する場合:
       1. GitLab Duoサイドバーで、**新しいチャットを追加**（{{< icon name="pencil-square" >}}）を選択します。
       1. ドロップダウンリストで、エージェントを選択します。
     - 既存の会話と同じエージェントとの新しい会話を作成する場合は、メッセージボックスに`/new`と入力し、<kbd>Enter</kbd>を押すか、**送信**を選択します。

     新しいChatの会話で既存の会話が置き換えられます。

   - Chatテキストボックスの下で、**エージェント**切替がオンになっていることを確認します。
   - IDEでは、パネル上部で**新しいチャット**（{{< icon name="plus" >}}）を選択します。クラシックレイアウトでは、**新しいチャット**はメッセージボックスの右上隅にあります。

1. 質問を入力し、<kbd>Enter</kbd>キーを押すか、**送信**を選択します。
1. すべての会話を表示するには、[chat history](#view-the-chat-history)を確認します。
1. 会話を切り替えるには、チャット履歴で適切な会話を選択します。
1. チャット履歴で特定の会話を検索するには:
   - GitLab UI: **スレッドを検索**テキストボックスに検索語句を入力します。
   - IDE: **履歴を検索**テキストボックスに検索語を入力します。クラシックレイアウトでは、**チャットを検索**テキストボックスを使用します。

LLMコンテキストウィンドウの制限により、会話はそれぞれ200,000トークン（約800,000文字）に切り詰められます。

## 会話を削除する {#delete-a-conversation}

{{< history >}}

- 会話を削除する機能がGitLab 18.2で[導入](https://gitlab.com/gitlab-org/gitlab/-/issues/545289)されました。

{{< /history >}}

1. GitLab UIまたはIDEで、[chat history](#view-the-chat-history)を選択します。
1. 履歴で、**このチャットを削除**（{{< icon name="remove" >}}）を選択します。

個々の会話は、30日間の非アクティブ状態後に有効期限が切れ、自動的に削除されます。

## ローカル環境でGitLab Duo Chatをカスタマイズする {#customize-gitlab-duo-chat-in-your-local-environment}

コーディングスタイル、チームのプラクティス、プロジェクトの要件を反映した指示を指定することで、ローカル環境でのGitLab Duo Chatの動作をカスタマイズできます。

GitLab Duo Chatは、次の2つのアプローチをサポートしています:

- `chat-rules.md`の[カスタムルール](../duo_agent_platform/customize/custom_rules.md): GitLab専用。個人の設定やチームの標準に最適です。
- [`AGENTS.md`の共有ルール](../duo_agent_platform/customize/agents_md.md): GitLab、および`AGENTS.md`仕様をサポートするその他のAIツールで使用できます。プロジェクトのコンテキスト、モノレポの構成、ディレクトリ固有の規則に最適です。

両方のファイルを同時に使用できます。GitLab Duo Chatは、利用可能なすべてのルールファイルの指示を適用します。

[GitLab Duoをカスタマイズ](../duo_agent_platform/customize/_index.md)する方法について詳細をご覧ください。

## モデルを選択する {#select-a-model}

{{< details >}}

- 提供形態: GitLab.com、GitLab Self-Managed

{{< /details >}}

{{< history >}}

- GitLab 18.4で`ai_user_model_switching`[フラグ](../../administration/feature_flags/_index.md)とともに[ベータ版](../../policy/development_stages_support.md#beta)機能として[導入](https://gitlab.com/groups/gitlab-org/-/epics/19251)されました。デフォルトでは無効になっています。
- GitLab 18.4で[有効](https://gitlab.com/gitlab-org/gitlab/-/issues/560319)になりました。
- GitLab 18.6の[GitLab Self-Managedで利用可能](https://gitlab.com/groups/gitlab-org/-/epics/19344)になりました。
- GitLab 18.6でVS CodeおよびJetBrains IDEに[追加](https://gitlab.com/groups/gitlab-org/-/epics/19345)されました。
- 機能フラグ`ai_user_model_switching`はGitLab 18.7で[削除](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/214042)されました。
- GitLab 18.8で[一般提供](https://gitlab.com/gitlab-org/gitlab/-/work_items/569140)になりました。

{{< /history >}}

GitLab UI、VS Code、またはJetBrains IDEでChatを使用する場合、会話に使用するモデルを選択できます。

チャット履歴から以前のチャットを開いてその会話を続けると、Chatは以前に選択したモデルを使用します。

既存の会話中に新しいモデルを選択すると、チャットは新たに選択したモデルで現在の会話を続行します。

前提条件: 

{{< tabs >}}

{{< tab title=GitLab.com >}}

- トップレベルグループのオーナーロールを持つユーザーが、Agentic Chat用のモデルを固定していません。[Agentic Chatを特定のモデルに制限せずにデフォルト以外のモデルを選択した](../duo_agent_platform/model_selection.md#select-a-model-for-agentic-chat)場合、そのモデルは固定され、変更できません。それ以外の場合は、利用可能なモデルから選択できます。
- トップレベルグループでChatを使用している。組織内でChatにアクセスしている場合、モデルを変更することはできません。

{{< /tab >}}

{{< tab title="GitLab Self-Managed" >}}

- 管理者がAgentic Chat用のモデルを固定していません。[Agentic Chatを特定のモデルに制限せずにデフォルト以外のモデルを選択した](../../administration/gitlab_duo/model_selection.md#select-a-model-for-agentic-chat)場合、そのモデルは固定され、変更できません。それ以外の場合は、利用可能なモデルから選択できます。
- インスタンスがGitLab AIゲートウェイに接続されている。

{{< /tab >}}

{{< /tabs >}}

モデルを選択するには:

- GitLab UIの場合: 
  1. チャットテキストボックスの下で、**エージェント**切替がオンになっていることを確認します。
  1. ドロップダウンリストからモデルを選択します。
- IDEの場合: 
  1. サイドバーで、**GitLab Duo Agent Platform**（{{< icon name="duo-agentic-chat" >}}）を選択します。
  1. [クラシックレイアウト](#change-the-layout-in-your-ide)を使用している場合は、**チャット**タブを選択します。
  1. ドロップダウンリストからモデルを選択します。

## エージェントを選択する {#select-an-agent}

{{< history >}}

- GitLab 18.4で[導入](https://gitlab.com/gitlab-org/gitlab/-/issues/562708)されました。
- GitLab 18.5でVS CodeおよびJetBrains IDEに[追加](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/merge_requests/2196)されました。

{{< /history >}}

GitLab UI、VS Code、またはJetBrains IDEのプロジェクトでChatを使用する場合、Chatで使用する特定のエージェントを選択できます。

前提条件: 

- プロジェクトで[AIカタログのエージェントが有効](../duo_agent_platform/agents/custom.md#enable-an-agent)になっている。
- そのエージェントが有効になっているプロジェクトのメンバーである。
- VS Codeの場合、バージョン6.49.12以降の[GitLab for VS Code拡張機能をインストールして設定](../../editor_extensions/visual_studio_code/setup.md)している。
- JetBrains IDEの場合、バージョン3.22.0以降の[JetBrains IDE用GitLab Duoプラグインをインストールして設定](../../editor_extensions/jetbrains_ide/setup.md)している。

エージェントを選択するには:

1. GitLab UIまたはIDEで、GitLab Duo Chatの新しい会話を開きます。
1. GitLab UIのChatテキストボックスの下で、**エージェント**切替がオンになっていることを確認します。
1. ドロップダウンリストで、エージェントを選択します。エージェントを設定していない場合、ドロップダウンリストはなく、ChatはデフォルトのGitLab Duoエージェントを使用します。
1. 質問を入力し、<kbd>Enter</kbd>キーを押すか、**送信**を選択します。

エージェントとの会話を作成した後:

- 会話では選択したエージェントが記憶されます。その会話で別のエージェントを選択することはできません。新しいIDEレイアウトでは、別のエージェントを選択すると、チャットは確認を求めてから新しい会話を開始します。
- チャット履歴を使用して同じ会話に戻ると、同じエージェントが使用されます。
- 会話に戻ったときに、関連付けられているエージェントが利用できなくなっている場合、その会話を続けることはできません。

## プロンプトキャッシュ {#prompt-caching}

{{< history >}}

- GitLab 18.7で導入されました。

{{< /history >}}

プロンプトキャッシュはデフォルトで有効になっており、選択されたAgentic ChatモデルがAnthropicから直接提供されるモデル、またはVertex経由で提供されるAnthropicモデルである場合にのみ機能します。

プロンプトキャッシュが有効な場合、チャットプロンプトデータはモデルベンダーによって一時的にメモリに保存されます。

プロンプトキャッシュにより、キャッシュされたプロンプトと入力データの再処理を回避できるため、レイテンシーが大幅に改善されます。

次の場所で、[プロンプトキャッシュをオフに](../gitlab_duo/data_usage.md#turn-off-prompt-caching)できます:

- GitLab.com: トップレベルグループ。
- GitLab Self-Managed: インスタンス。

この設定は、GitLab Duo Agent Platformのすべての機能に適用されます。

## ツールの承認 {#tool-approvals}

{{< history >}}

- GitLab 19.0で[導入](https://gitlab.com/groups/gitlab-org/-/work_items/20519)されました
  - [GitLab for VS Code](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.72.0) 6.72.0で導入されました
  - [JetBrains IDE用GitLab Duoプラグイン](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.33.0)3.33.0で導入されました
  - [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.80.0) 8.80.0で導入されました。
- GitLab 19.1でパターンベースのツール承認が[導入](https://gitlab.com/groups/gitlab-org/-/work_items/21850)されました。
  - [GitLab for VS Code](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.83.2) 6.83.2で導入されました。
  - [JetBrains IDE用GitLab Duoプラグイン](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.38.0)3.38.0で導入されました。
  - [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.101.0) 8.101.0で導入されました。
- パターンベースのツール承認は、2026年7月10日に[削除](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/merge_requests/3699)されました。
  - [GitLab for VS Code](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.85.3) 6.85.3で削除されました。
  - [JetBrains IDE用GitLab Duoプラグイン](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.43.0)3.43.0で削除されました。
  - [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.3.0) 9.3.0で削除されました。

{{< /history >}}

Agentic Chatがユーザーに代わってツールを使用するには、ユーザーの承認が必要です。デフォルトでは、ツールを呼び出すたびに承認が必要です。

ツールを信頼しており、ワークフローを効率化する場合は、セッション全体に対して一度だけ承認することもできます。

セッション承認はChatにのみ適用され、フローには適用されません。

### ツールの承認を管理する {#manage-tool-approvals}

オーナーと管理者は、ユーザーがセッションに対してツールを承認できるかどうかを制御できます。設定は、インスタンスからグループ、プロジェクトへとカスケードされます。

グループまたはインスタンスに対して、次のいずれかのオプションを設定します:

- **デフォルトでオン**: ユーザーはセッションに対してツールを一度だけ承認できます。グループおよびサブグループでは、この設定をオフにできます。
- **デフォルトでオフ**: （デフォルト）ユーザーはツールを呼び出すたびに承認する必要があります。グループおよびサブグループでは、この設定をオンにできます。
- **常にオフ**: ユーザーはセッションに対してツールを承認できません。グループおよびサブグループでは、この設定をオーバーライドできません。

#### デフォルト設定を管理する {#manage-default-settings}

インスタンスまたはトップレベルグループのデフォルトのツール承認設定を構成します。

{{< tabs >}}

{{< tab title="GitLab.com" >}}

前提条件: 

- トップレベルグループのオーナーロール。

デフォルトのツール承認設定を構成するには:

1. 上部のバーで、**検索または移動先**を選択して、グループを見つけます。
1. **設定** > **GitLab Duo**を選択します。
1. **セッションに対するツールの承認**ドロップダウンリストから、希望するオプションを選択します。

{{< /tab >}}

{{< tab title="GitLab Self-Managed" >}}

前提条件: 

- 管理者アクセス権。

デフォルトのツール承認設定を構成するには:

1. 右上隅で、**管理者**を選択します。
1. **GitLab Duo**を選択します。
1. **セッションに対するツールの承認**ドロップダウンリストから、希望するオプションを選択します。

{{< /tab >}}

{{< tab title="GitLab Dedicated" >}}

前提条件: 

- 管理者アクセス権。

デフォルトのツール承認設定を構成するには:

1. 右上隅で、**管理者**を選択します。
1. **GitLab Duo**を選択します。
1. **セッションに対するツールの承認**ドロップダウンリストから、希望するオプションを選択します。

{{< /tab >}}

{{< /tabs >}}

#### グループまたはプロジェクトの設定を管理する {#manage-group-or-project-settings}

特定のグループまたはプロジェクトのツール承認設定を構成します。

前提条件: 

- グループのオーナーロール、またはプロジェクトのメンテナーロール。

ツール承認設定を構成するには:

1. 上部のバーで**検索または移動先**を選択し、グループまたはプロジェクトを見つけます。
1. **設定** > **GitLab Duo**を選択します。
1. グループの場合、**セッションに対するツールの承認**ドロップダウンリストから、希望するオプションを選択します。
1. プロジェクトの場合、**セッションに対するツールの承認を許可**チェックボックスをオンまたはオフにします。

### ローカル環境でツールを承認する {#approve-tools-in-your-local-environment}

前提条件: 

- グループまたはインスタンスでツールの承認が有効になっている必要があります。
- ローカル環境でGitLab Duo Chatについて、次のいずれかをインストールして設定している必要があります:
  - [GitLab for VS Code](../../editor_extensions/visual_studio_code/setup.md) 6.72.0以降。
  - [JetBrains IDE用GitLab Duoプラグイン](../../editor_extensions/jetbrains_ide/setup.md)3.33.0以降。
  - [GitLab Duo CLI](../gitlab_duo_cli/_index.md) 8.80.0以降。

現在のセッションでツールを承認または拒否するには:

1. ツールの承認プロンプトが表示されたら、承認ボタンの横にあるドロップダウンを選択します。
1. 次のいずれかのオプションを選択します:
   - **承認**: Chatは、この引数を指定してツールを1回使用できます。
   - **セッションで承認**: Chatは、セッションの残りの期間、この引数を指定してツールを使用できます。別の引数を使用する場合は、追加の承認が必要です。
   - **拒否**: Chatはこのツールを使用できません。

新しい会話を開始すると、すべての承認がリセットされます。

## Chat機能の比較 {#chat-feature-comparison}

| 機能                                     | GitLab Duo Non-Agentic Chat                                              | GitLab Duo Agentic Chat                                                                                           |
| ---------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| 一般的なプログラミングの質問をする              | はい                                                                      | はい                                                                                                               |
| エディタで開いているファイルに関する回答を得る   | はい                                                                      | はい。ただし、質問内でファイルのパスを指定する必要があります。                                                               |
| 指定されたファイルに関するコンテキストを提供する          | はい。`/include`を使用して、会話にファイルを追加します。[^not-in-ide-chat] | はい。ただし、質問内でファイルのパスを指定する必要があります。新しいIDEレイアウトでは、`@`と入力してファイルを追加することもできます。 |
| プロジェクトコンテンツを自律的に検索する           | いいえ                                                                       | はい                                                                                                               |
| ファイルを自律的に作成および変更する     | いいえ                                                                       | はい。ファイルを変更するように依頼する必要があります。手動で行い、まだコミットしていない変更を上書きする可能性があります。   |
| IDを指定せずにイシューとMRを取得する | いいえ                                                                       | はい。他の条件で検索します。たとえば、MR、イシューのタイトル、担当者などです。                                   |
| 複数のソースからの情報を統合する      | いいえ                                                                       | はい                                                                                                               |
| パイプラインログを分析する                          | はい。GitLab Duo Enterpriseアドオンが必要です。                              | はい                                                                                                               |
| 会話を再開する                         | はい。`/new`または`/reset`を使用します。                                             | はい。`/new`を使用するか、UIの場合は`/reset`を使用します。                                                                       |
| 会話を削除する                          | はい、チャット履歴から削除できます。                                                | はい、チャット履歴から削除できます                                                                                          |
| イシューとMRを作成する                          | いいえ                                                                       | はい                                                                                                               |
| Git読み取り専用コマンドを使用する                     | いいえ                                                                       | はい                                                                                                               |
| Git書き込みコマンドを使用する                         | いいえ                                                                       | はい、UIのみ                                                                                                      |
| Shellコマンドを実行する                             | いいえ                                                                       | はい、IDEのみ                                                                                                    |
| MCPツールを実行する                                  | いいえ                                                                       | はい、IDEのみ                                                                                                    |
| セッションに対してツールを承認する                    | いいえ                                                                       | はい、IDEのみ                                                                                                    |

[^not-in-ide-chat]: Web IDEでGitLab Duo Non-Agentic Chatを使用している場合は利用できません。

## 関連トピック {#related-topics}

- [ブログ: GitLab Duo Chat gets agentic AI makeover](https://about.gitlab.com/blog/gitlab-duo-chat-gets-agentic-ai-makeover/)
