---
stage: Security Governance
group: Security Controls
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: セキュリティ設定プロファイルを管理する
---

{{< details >}}

- プラン: Ultimate
- 提供形態: GitLab.com、GitLab Self-Managed、GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.9で`security_scan_profiles_feature`[機能フラグ](../../../administration/feature_flags/_index.md)とともに[導入](https://gitlab.com/groups/gitlab-org/-/work_items/19802)されました。デフォルトでは有効になっています。
- GitLab 18.10でシークレット検出プロファイルが[追加](https://gitlab.com/groups/gitlab-org/-/epics/19903)されました。
- GitLab 18.11でSASTプロファイルが[追加](https://gitlab.com/groups/gitlab-org/-/epics/19951)されました。
- GitLab 19.0で依存関係スキャンプロファイルが`security_scan_profiles_dependency_scanning`[機能フラグ](../../../administration/feature_flags/_index.md)とともに[導入](https://gitlab.com/groups/gitlab-org/-/epics/19952)されました。デフォルトでは有効になっています。
- GitLab 19.2で依存関係スキャンの自動修正プロファイルが`security_remediation_profiles`[機能フラグ](../../../administration/feature_flags/_index.md)とともに[導入](https://gitlab.com/groups/gitlab-org/-/work_items/604588)されました。デフォルトでは有効になっています。
- GitLab 19.3でシークレット検出スキャンプロファイル設定が[実験的機能](../../../policy/development_stages_support.md)として[導入](https://gitlab.com/gitlab-org/gitlab/-/work_items/606237)され、GraphQL APIでのみ利用できます。
- 機能フラグ`security_scan_profiles_feature`はGitLab 19.4で削除されました。
- 機能フラグ`security_remediation_profiles`はGitLab 19.4で削除されました。
- GitLab 19.4でSASTスキャンプロファイル設定が[実験的機能](../../../policy/development_stages_support.md)として[導入](https://gitlab.com/gitlab-org/gitlab/-/work_items/617070)され、GraphQL APIでのみ利用できます。
- 依存関係スキャンのスキャンプロファイル設定は、GitLab 19.5で[実験](../../../policy/development_stages_support.md#experiment)として[導入](https://gitlab.com/gitlab-org/gitlab/-/work_items/629403)され、GraphQL APIからのみ使用できます。
- UIのカスタムプロファイルは、GitLab 19.4で`custom_scan_profiles_ui`という名前の[機能フラグを使用して](../../../administration/feature_flags/_index.md) [導入](https://gitlab.com/gitlab-org/gitlab/-/work_items/624191)されました。デフォルトでは無効になっています。
- GitLab 19.5で[GitLab.com、GitLab Self-Managed、GitLab Dedicatedで有効化](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259962)されました。

{{< /history >}}

セキュリティ設定プロファイルは、プロジェクト全体でセキュリティスキャナーをどのように、いつ実行するかを定義する集中化された設定です。セキュリティ設定プロファイルを使用して、組織全体のセキュリティスキャナーを効率的に管理します。プロファイルベースのアプローチにより、手動設定を最小限に抑えながらベストプラクティスを適用できます。

<i class="fa-youtube-play" aria-hidden="true"></i> 概要については、[セキュリティ設定プロファイルの紹介](https://www.youtube.com/watch?v=QbnLGzTEqGI)を参照してください。

グループにプロファイルを適用すると、そのグループ内の個々のプロジェクトすべてに適用されます。プロファイルはグループ自体にはアタッチされず、プロファイル間でもサブグループ間でも継承されません。

[デフォルトプロファイル](#default-profiles)を使用すると、最小限の設定で、事前設定済みのセキュリティスキャンを数分で有効にできます。

## セキュリティスキャナーを設定する {#configure-security-scanners}

プロファイルを評価および管理するには、グループの[セキュリティインベントリ](../security_inventory/_index.md#view-the-security-inventory)を一元化されたダッシュボードとして使用します。

### テストカバレッジをレビューする {#review-test-coverage}

グループ内のSAST、依存関係スキャン、シークレット検出などのスキャナーについて、概要レベルのステータス（**有効**、**無効**、**失敗**）を確認するには:

1. 上部のバーで、**検索または移動先**を選択して、グループを見つけます。
1. 左側のサイドバーで、**セキュリティ** > **セキュリティインベントリ**を選択します。
1. セキュリティインベントリで、**テストカバレッジ**列をレビューします。

### 個々のプロジェクトのカバレッジを変更する {#change-individual-project-coverage}

特定のプロジェクトを設定するには:

1. 上部のバーで、**検索または移動先**を選択して、グループを見つけます。
1. 左側のサイドバーで、**セキュリティ** > **セキュリティインベントリ**を選択します。
1. プロジェクトの横にある縦方向の省略記号（{{< icon name="ellipsis_v" >}}）を選択し、**ツールのカバレッジを管理**を選択します。
1. 個々のスキャナーをオンまたはオフにします。

### 複数のプロジェクトにプロファイルを適用する {#apply-a-profile-to-multiple-projects}

時間を節約するために、複数のプロジェクトにセキュリティ設定を一度に適用できます:

1. 上部のバーで、**検索または移動先**を選択して、グループを見つけます。
1. 左側のサイドバーで、**セキュリティ** > **セキュリティインベントリ**を選択します。
1. 複数のプロジェクトまたはサブグループ全体を選択して、設定を適用します。
1. **一括アクション**ドロップダウンを選択し、**セキュリティスキャナーの管理**を選択します。
1. **デフォルトプロファイルを全てに適用**を選択して、選択範囲全体のセキュリティ対策状況を標準化します。

## デフォルトプロファイル {#default-profiles}

GitLabには、事前設定済みのスキャナー設定であるデフォルトプロファイルが用意されているため、最小限の設定でセキュリティスキャンを有効にできます。

### シークレット検出プロファイル {#secret-detection-profile}

シークレット検出プロファイルを適用すると、開発ワークフロー全体でシークレットに対する推奨されるベースライン保護が有効になります。このプロファイルでは、次のスキャントリガーが有効になります:

- **プッシュ保護**: すべてのGitプッシュイベントをスキャンし、シークレットが検出されたプッシュをブロックすることで、シークレットがコードベースに含まれるのを防ぎます。
- **マージリクエストパイプライン**: オープンなマージリクエストのあるブランチに新しいコミットがプッシュされるたびに、スキャンを自動的に実行します。結果には、マージリクエストによって新たに導入された脆弱性のみが含まれます。すべてのブランチが対象です。
- **ブランチパイプライン（デフォルトのみ）**: 変更がデフォルトブランチにマージまたはプッシュされると自動的に実行され、デフォルトブランチのシークレット検出の状況を包括的に把握できます。すべてのブランチが対象です。

### SASTプロファイル {#sast-profile}

SASTプロファイルを適用すると、推奨設定を使用してプロジェクト全体で静的アプリケーションセキュリティテストが有効になります。このプロファイルでは、次のスキャントリガーが有効になります:

- **マージリクエストパイプライン**: オープンなマージリクエストがあるブランチに新しいコミットがプッシュされるたびに、SASTスキャンを自動的に実行します。結果には、マージリクエストによって新たに導入された脆弱性のみが含まれます。すべてのブランチが対象です。
- **ブランチパイプライン（デフォルトのみ）**: 変更がデフォルトブランチにマージまたはプッシュされると自動的に実行され、デフォルトブランチのSASTの状況を包括的に把握できます。デフォルトブランチが対象です。

### 依存関係スキャンプロファイル {#dependency-scanning-profile}

依存関係スキャンプロファイルを有効にすると、推奨設定を使用して、プロジェクトの依存関係に既知の脆弱性がないかスキャンされます。このプロファイルでは、次のスキャントリガーが有効になります:

- **マージリクエストパイプライン**: オープンなマージリクエストがあるブランチに新しいコミットがプッシュされるたびに、依存関係スキャンを自動的に実行します。結果には、マージリクエストによって新たに導入された脆弱性のみが含まれます。すべてのブランチが対象です。
- **ブランチパイプライン（デフォルトのみ）**: 変更がデフォルトブランチにマージまたはプッシュされると自動的に実行され、デフォルトブランチの依存関係における脆弱性の状況を包括的に把握できます。デフォルトブランチが対象です。

### 依存関係スキャンの自動修正プロファイル {#dependency-scanning-auto-remediation-profile}

{{< history >}}

- GitLab 19.4で自動修正向けのトリアージおよび修正プロファイルのサポートが`triage_and_remediation_profile`[機能フラグ](../../../administration/feature_flags/_index.md)とともに[導入](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253780)されました。デフォルトでは有効になっています。

{{< /history >}}

依存関係スキャンの自動修正プロファイルを有効にすると、GitLabは脆弱な依存関係を脆弱性のないバージョンに更新するマージリクエストを作成します。この機能の詳細については、[依存関係スキャンの自動修正](../remediate/dependency_scanning_auto_remediation.md)を参照してください。

[GitLab CLI](../../../editor_extensions/gitlab_cli/_index.md)（`glab`）を使用して、プロファイルをプロジェクトにアタッチします:

```shell
glab security config enable dependency_scanning_post_processing -R <project-path>
```

たとえば、`my-group/my-project`のプロファイルを有効にするには:

```shell
glab security config enable dependency_scanning_post_processing -R my-group/my-project
```

> [!note]
> 1つのプロジェクトに両方のプロファイルを同時にアタッチできます。その場合、GitLabは先に適用されたプロファイルのみを使用します。もう一方のプロファイルの設定は無視されます。

### 自動トリアージおよび修正プロファイル {#automated-triage-and-remediation-profile}

{{< history >}}

- GitLab 19.4でトリアージおよび修正プロファイルが`triage_and_remediation_profile`[機能フラグ](../../../administration/feature_flags/_index.md)とともに[導入](https://gitlab.com/gitlab-org/gitlab/-/issues/622469)されました。デフォルトでは有効になっています。

{{< /history >}}

> [!flag]
> この機能の利用可否は、機能フラグによって制御されます。詳細については、履歴を参照してください。

トリアージおよび修正プロファイルを使用すると、プロジェクトおよびグループ全体でGitLab Duoのトリアージフローと依存関係スキャンの自動修正を有効にできます。GitLab DuoのフローはAIを使用して検出結果を評価し、解決します。プロファイルでは、フローを単独で有効にすることも、同等のプロジェクト単位の設定が存在する場合はその設定を置き換えることもできます。

GitLabでは次の3つのプリセットが用意されています: Conservative、Standard、Proactive。それぞれのプリセットでは、各フローに異なる設定を適用するため、フローがどの範囲で、どの程度の頻度でトリガーされ、実行されるかを選択できます。プロファイルを作成し、独自に設定することもできます。

前提条件: 

- [GitLab Duo Agent Platformの前提条件](../../duo_agent_platform/_index.md#prerequisites)を満たしていること。
- [トップレベルグループ](../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off)で、**基本フローを許可**と、使用する各フローを有効にしていること。フローはプロジェクトごとではなく、トップレベルグループに対して一度だけ有効にします。

> [!note]
> これらのフローのほとんどはAIを活用しており、[GitLabクレジット](../../../subscriptions/gitlab_credits.md)を消費します。消費量は検出結果の数に応じて増加します。

#### プリセット {#presets}

| フロー | Conservative | Standard | Proactive |
| ---- | ------------ | -------- | --------- |
| SASTの誤検出判定 | `high`以上、オンデマンド | `medium`以上、自動 | `info`以上、自動 |
| SAST脆弱性の修正 | `high`以上、オンデマンド、オープンなマージリクエストは最大5件 | `medium`以上、自動、オープンなマージリクエストは最大15件 | `info`以上、自動、マージリクエスト数の上限なし |
| シークレット誤検出判定 | `high`以上、オンデマンド | `medium`以上、自動 | `info`以上、自動 |
| 依存関係スキャンの自動修正 | `high`以上、マイナーバージョンアップグレード、オープンなマージリクエストは最大5件、過去7日以内の修正バージョンをスキップ | `high`以上、マイナーバージョンアップグレード、オープンなマージリクエストは最大10件、過去7日以内の修正バージョンをスキップ | `info`以上、メジャーバージョンアップグレード、オープンなマージリクエストは最大10件、過去7日以内の修正バージョンをスキップ |

プリセットを適用するには、[GraphQL API](#apply-a-profile-with-the-graphql-api)を使用します。プリセット名は`Triage and Remediation (Conservative)`、`Triage and Remediation (Standard)`、`Triage and Remediation (Proactive)`です。

#### 関連トピック {#related-topics}

- [誤検出を自動的に検出する](../vulnerabilities/false_positive_detection.md)
- [エージェント型SAST脆弱性の修正](../vulnerabilities/agentic_vulnerability_resolution.md)
- [シークレット誤検出判定](../vulnerabilities/secret_false_positive_detection.md)
- [依存関係スキャンの自動修正](../remediate/dependency_scanning_auto_remediation.md)

### ビジネスロジックプロファイル {#business-logic-profile}

{{< details >}}

- ステータス: 実験的機能

{{< /details >}}

{{< history >}}

- GitLab 19.5で`bl_security_analyzer`[機能フラグ](../../../administration/feature_flags/_index.md)とともに[導入](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257199)されました。デフォルトでは無効になっています。

{{< /history >}}

> [!flag]
> この機能の利用可否は、機能フラグによって制御されます。詳細については、履歴を参照してください。

ビジネスロジックプロファイルは、AIエージェントを使用して、認可の欠落、オブジェクトレベルのアクセス制御の不備、マスアサインメントなどのビジネスロジックの脆弱性を検出します。プロファイルをプロジェクトにアタッチすると、そのプロジェクトでスキャンが有効になります。

マージリクエストのHEADパイプラインが成功すると、マージリクエストが追加または変更したファイルに対してスキャンが実行されます。デフォルトブランチのパイプラインでは実行されません。デフォルトブランチをカバーするには、[GitLab Duo Chatからスキャンを開始](../business_logic_scanning/_index.md#start-a-scan-from-gitlab-duo-chat)してください。プロジェクトにCI/CDパイプラインがない場合、マージリクエストのスキャンは実行されません。

[トップレベルグループ](../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off)で**フロー実行を許可**、**基本フローを許可**、**ビジネスロジックセキュリティスキャンフロー**を有効にします。

前提条件とスキャンで検出される内容の詳細については、[ビジネスロジックスキャン](../business_logic_scanning/_index.md)を参照してください。

### プロファイルの詳細を表示する {#view-details-about-a-profile}

シークレット検出プロファイルの技術的な詳細を表示するには:

1. 上部のバーで、**検索または移動先**を選択して、グループを見つけます。
1. 左側のサイドバーで、**セキュリティ** > **セキュリティインベントリ**を選択します。
1. **シークレット検出**プロファイルを選択します。
1. 次の情報を確認します:
   - **アナライザータイプ**: プロファイルのタイプ（例: **シークレット検出**、**SAST**、**依存関係スキャン**）。
   - **スキャントリガー**: プロファイルでサポートされているトリガー（例: **プッシュ保護**、**マージリクエストパイプライン**、**ブランチパイプライン**）。
   - **ステータス**: カバレッジステータスインジケーターを使用して、現在のコンテキストでプロファイルが現在**アクティブ**か**無効**かを表示します。

## スキャナー有効化ウィザードを使用してスキャナーを有効にする {#enable-scanners-with-the-scanner-enablement-wizard}

スキャナーが有効になっていないプロジェクトにプロファイルを適用するには、[スキャナー有効化ウィザード](scanner_enablement_wizard.md)を使用します。このウィザードでは、スキャナーが有効になっていないプロジェクトを特定し、グループ全体にデフォルトプロファイルまたはカスタムプロファイルを適用できます。

## GraphQL APIでプロファイルを適用する {#apply-a-profile-with-the-graphql-api}

GraphQL APIを使用すると、UIではまだ利用できないプロファイルを含め、任意のセキュリティ設定プロファイルを適用できます。これらのクエリは、[インタラクティブGraphQLエクスプローラー](../../../api/graphql/_index.md#interactive-graphql-explorer)で実行するか、`/api/graphql`エンドポイントに直接リクエストを送信することで実行できます。

クエリの実行、認証、ページネーションの詳細については、[GraphQL APIのクエリとミューテーションを実行する](../../../api/graphql/getting_started.md)を参照してください。

前提条件: 

- 関連するプロジェクトまたはグループで、メンテナーロールまたはセキュリティマネージャーロール以上が必要です。

セキュリティ設定プロファイルを適用するには:

1. グループで利用可能なプロファイルとそのIDを取得します:

```graphql
   query {
     group(fullPath: "my-group") {
       availableSecurityScanProfiles {
         id
         name
         scanType
       }
     }
   }
```

   まだ保存されていないデフォルトプロファイルの場合、スキャンタイプに基づく仮想IDが返されます。例: `gid://gitlab/Security::ScanProfile/dependency_scanning_post_processing`。

   詳細については、[`Group.availableSecurityScanProfiles`フィールド](../../../api/graphql/reference/_index.md#groupavailablesecurityscanprofiles)を参照してください。

1. 適用するプロファイルの仮想IDまたは実際のIDを指定して、`securityScanProfileAttach`ミューテーションでプロファイルを適用します:

```graphql
   mutation {
     securityScanProfileAttach(input: {
       securityScanProfileId: "gid://gitlab/Security::ScanProfile/dependency_scanning_post_processing",
       projectIds: ["gid://gitlab/Project/123"]
     }) {
       errors
     }
   }
```

   詳細については、[`securityScanProfileAttach`ミューテーション](../../../api/graphql/reference/_index.md#mutationsecurityscanprofileattach)を参照してください。

1. プロファイルの適用先を選択するには、次の引数のいずれかまたは両方を設定します:
   - `projectIds`: 特定のプロジェクトにプロファイルを適用します。
   - `groupIds`: 1つ以上のグループ内のすべてのプロジェクトにプロファイルを適用します。

   指定するすべてのプロジェクトとグループは、同じトップレベルグループに属している必要があります。1回のミューテーションで指定できるIDは、プロジェクトIDとグループIDを合わせて最大100個です。

1. プロファイルが適用されたことを確認するには、レスポンスの`errors`フィールドをチェックします。

## シークレット検出プロファイルをカスタマイズする {#customize-a-secret-detection-profile}

{{< details >}}

- ステータス: 実験的機能

{{< /details >}}

> [!flag]
> この機能の利用可否は、機能フラグによって制御されます。詳細については、履歴を参照してください。

シークレット検出プロファイルをカスタマイズすると、スキャナーの実行時に使用される設定をオーバーライドできます。各設定は、既存の[シークレット検出CI/CD変数](../secret_detection/_index.md)にマップされます。

シークレット検出プロファイルは、UIまたはGraphQL APIでカスタマイズできます。

前提条件: 

- 関連するグループのメンテナーまたはセキュリティマネージャーロールが必要です。

UIでシークレット検出プロファイルをカスタマイズするには、次の手順に従います:

1. 上部のバーで、**検索または移動先**を選択して、グループを見つけます。
1. 左側のサイドバーで、**セキュリティ** > **セキュリティ設定**を選択します。
1. **スキャナー**タブを選択します。
1. **シークレット検出**行で、**プロファイルの管理**を選択します。
1. **新しいプロファイルを作成**を選択します。
1. **名前**と**説明**を入力します。
1. **スキャントリガー**で、使用するトリガーをオンにします。
1. オプション。必要に応じて、**高度な設定**でオーバーライドする設定を追加します。
1. **プロファイルの作成**を選択します。

後でプロファイルを変更するには、プロファイルを選択してから縦方向の省略記号（{{< icon name="ellipsis_v" >}}） > **編集**を選択し、**変更を保存**を選択します。変更は、そのプロファイルを使用するすべてのプロジェクトに適用されます。

GraphQL APIでシークレット検出プロファイルをカスタマイズするには、`securityScanProfileCreate`または`securityScanProfileUpdate`ミューテーションを使用します。カスタマイズするトリガーに`configuration.secretDetection`オブジェクトを設定します。

| フィールド | UI設定 | 説明 | 対応するCI/CD変数 |
| ----- | ---------- | ----------- | ------------------------- |
| `secureAnalyzersPrefix` | **アナライザーイメージレジストリ** | アナライザーイメージのプル元となるコンテナレジストリのプレフィックス。 | `SECURE_ANALYZERS_PREFIX` |
| `imageSuffix` | **イメージバリアント**（Default、FIPS） | アナライザーイメージ名に追加するサフィックス。`DEFAULT`または`FIPS`に設定します。 | `SECRET_DETECTION_IMAGE_SUFFIX` |
| `historicScan` | **過去のスキャン** | 現在の状態だけでなく、Git履歴全体をスキャンするかどうか。 | `SECRET_DETECTION_HISTORIC_SCAN` |
| `logOptions` | **ログのオプション** | スキャンするコミット範囲を制御するために`git log`に渡すオプション。 | `SECRET_DETECTION_LOG_OPTIONS` |
| `excludedPaths` | **除外するパス** | スキャンから除外するglobパス。 | `SECRET_DETECTION_EXCLUDED_PATHS` |
| `rulesetGitReference` | **ルールセットのGit参照** | 使用するリモートルールセット設定のGit参照。 | `SECRET_DETECTION_RULESET_GIT_REFERENCE` |

たとえば、カスタマイズしたマージリクエストパイプラインのトリガーを使用するシークレット検出プロファイルを作成するには:

```graphql
mutation {
  securityScanProfileCreate(input: {
    namespaceId: "gid://gitlab/Group/123",
    scanType: SECRET_DETECTION,
    name: "Custom secret detection profile",
    description: "Secret detection profile with a historic scan and path exclusions",
    triggers: [
      {
        triggerType: MERGE_REQUEST_PIPELINE,
        configuration: {
          secretDetection: {
            historicScan: true,
            excludedPaths: ["spec/**/*", "test/**/*"]
          }
        }
      }
    ]
  }) {
    scanProfile {
      id
      name
    }
    errors
  }
}
```

デフォルトでは、`stripDefaults`引数によって、デフォルト値と一致するトリガー設定値はプロファイルを保存する前に削除されるため、オーバーライドした値だけが保持されます。

引数の完全なリストについては、[`securityScanProfileCreate`ミューテーション](../../../api/graphql/reference/_index.md#mutationsecurityscanprofilecreate)を参照してください。

## SASTプロファイルをカスタマイズする {#customize-a-sast-profile}

> [!flag]
> この機能の利用可否は、機能フラグによって制御されます。詳細については、履歴を参照してください。

SASTプロファイルをカスタマイズすると、プロファイルの実行時に使用されるスキャナー設定をオーバーライドできます。各設定は、既存の[SAST CI/CD変数](../sast/_index.md)にマップされます。

これは[実験的機能](../../../policy/development_stages_support.md)です。SASTプロファイルは、UIまたはGraphQL APIでカスタマイズできます。

前提条件: 

- 関連するグループのメンテナーまたはセキュリティマネージャーロールが必要です。

UIでSASTプロファイルをカスタマイズするには、次の手順に従います:

1. 上部のバーで、**検索または移動先**を選択して、グループを見つけます。
1. 左側のサイドバーで、**セキュリティ** > **セキュリティ設定**を選択します。
1. **スキャナー**タブを選択します。
1. **静的アプリケーションセキュリティテスト（SAST）** 行で、**プロファイルの管理**を選択します。
1. **新しいプロファイルを作成**を選択します。
1. **名前**と**説明**を入力します。
1. **スキャントリガー**で、使用するトリガーをオンにします。
1. オプション。必要に応じて、**高度な設定**でオーバーライドする設定を追加します。
1. **プロファイルの作成**を選択します。

後でプロファイルを変更するには、プロファイルを選択してから縦方向の省略記号（{{< icon name="ellipsis_v" >}}） > **編集**を選択し、**変更を保存**を選択します。変更は、そのプロファイルを使用するすべてのプロジェクトに適用されます。

GraphQL APIでSASTプロファイルをカスタマイズするには、`securityScanProfileCreate`または`securityScanProfileUpdate`ミューテーションを使用します。カスタマイズするトリガーに`configuration.sast`オブジェクトを設定します。

| フィールド | UI設定 | 説明 | 対応するCI/CD変数 |
| ----- | ---------- | ----------- | ------------------------- |
| `secureAnalyzersPrefix` | **アナライザーイメージレジストリ** | アナライザーイメージのプル元となるコンテナレジストリのプレフィックス。 | `SECURE_ANALYZERS_PREFIX` |
| `imageSuffix` | **イメージバリアント**（Default、FIPS） | アナライザーイメージ名に追加するサフィックス。`DEFAULT`または`FIPS`に設定します。 | `SAST_IMAGE_SUFFIX` |
| `analyzerImageTag` | **アナライザーイメージタグ** | 使用するアナライザーイメージのタグ。すべてのSASTアナライザーに固定されたイメージタグをオーバーライドするため、特定のバージョンが必要な場合はアナライザーでエラーが発生する可能性があります。 | `SAST_ANALYZER_IMAGE_TAG` |
| `excludedAnalyzers` | **スキップするアナライザー** | スキャンから除外するアナライザー。 | `SAST_EXCLUDED_ANALYZERS` |
| `excludedPaths` | **除外するパス** | スキャンから除外するglobパス。 | `SAST_EXCLUDED_PATHS` |
| `advancedSastPartialScan` | **Advanced SASTの部分スキャン**（Enabled、Disabled） | GitLab高度なSASTの[差分ベーススキャン](../sast/gitlab_advanced_sast.md)を制御します。`DIFFERENTIAL`または`DISABLED`に設定します。 | `ADVANCED_SAST_PARTIAL_SCAN` |
| `gitlabAdvSastIncrScan` | **Advanced SASTのインクリメンタルスキャン** | GitLab高度なSASTで[増分スキャン](../sast/gitlab_advanced_sast.md)を有効にするかどうか。 | `GITLAB_ADV_SAST_INCR_SCAN` |

たとえば、カスタマイズしたマージリクエストパイプラインのトリガーを使用するSASTプロファイルを作成するには:

```graphql
mutation {
  securityScanProfileCreate(input: {
    namespaceId: "gid://gitlab/Group/123",
    scanType: SAST,
    name: "Custom SAST profile",
    description: "SAST profile with custom analyzer exclusions and Advanced SAST settings",
    triggers: [
      {
        triggerType: MERGE_REQUEST_PIPELINE,
        configuration: {
          sast: {
            excludedAnalyzers: ["eslint"],
            excludedPaths: ["spec/**/*", "test/**/*"],
            advancedSastPartialScan: DIFFERENTIAL,
            gitlabAdvSastIncrScan: true
          }
        }
      }
    ]
  }) {
    scanProfile {
      id
      name
    }
    errors
  }
}
```

各トリガーに指定できる設定項目は1つだけで、プロファイルのスキャンタイプと一致している必要があります。SASTプロファイルの場合、その項目は`sast`です。

デフォルトでは、`stripDefaults`引数によって、デフォルト値と一致するトリガー設定値はプロファイルを保存する前に削除されるため、オーバーライドした値だけが保持されます。

引数の完全なリストについては、[`securityScanProfileCreate`ミューテーション](../../../api/graphql/reference/_index.md#mutationsecurityscanprofilecreate)を参照してください。

## 依存関係スキャンプロファイルのカスタマイズ {#customize-a-dependency-scanning-profile}

{{< details >}}

- ステータス: 実験的機能

{{< /details >}}

依存関係スキャンプロファイルをカスタマイズして、スキャナーの実行時に使用される設定をオーバーライドします。各設定は、既存の[依存関係スキャンのCI/CD変数](../dependency_scanning/dependency_scanning_sbom/_index.md)にマップされます。

この機能は、GraphQL APIでのみ利用できます。

前提条件: 

- トップレベルグループのセキュリティマネージャー、メンテナー、またはオーナーのロール。

依存関係スキャンプロファイルをカスタマイズするには、次の手順に従います:

- `securityScanProfileCreate`または`securityScanProfileUpdate`ミューテーションで、カスタマイズするトリガーごとに`configuration.dependencyScanning`オブジェクトを設定します。

`dependencyScanning`オブジェクトは、次のフィールドをサポートします:

| フィールド | 説明 | 対応するCI/CD変数 |
| ----- | ----------- | ------------------------- |
| `secureAnalyzersPrefix` | アナライザーイメージのプル元となるコンテナレジストリのプレフィックス。 | `SECURE_ANALYZERS_PREFIX` |
| `additionalCaCertBundle` | 信頼するCA証明書バンドル。このバンドルはシステムの証明書に追加され、スキャン中に他のツールで使用されます。 | `ADDITIONAL_CA_CERT_BUNDLE` |
| `secureLogLevel` | アナライザーが使用するログレベル。`FATAL`、`ERROR`、`WARN`、`INFO`、または`DEBUG`に設定します。 | `SECURE_LOG_LEVEL` |
| `excludedPaths` | スキャンから除外するglobパス。 | `DS_EXCLUDED_PATHS` |
| `includeDevDependencies` | サポートされているファイルがスキャンされる際に、開発依存関係とテスト依存関係を含めるかどうか。 | `DS_INCLUDE_DEV_DEPENDENCIES` |
| `maxDepth` | アナライザーがスキャンするディレクトリの深さ。値を`-1`にすると、すべてのディレクトリをスキャンします。 | `DS_MAX_DEPTH` |
| `pipDependencyPath` | 分析用にPythonパッケージをインストールするために使用するパス。 | `DS_PIP_DEPENDENCY_PATH` |
| `staticReachabilityEnabled` | [静的到達可能性](../dependency_scanning/static_reachability.md)が有効かどうか。 | `DS_STATIC_REACHABILITY_ENABLED` |
| `enableManifestFallback` | ロックファイルまたは依存関係グラフのエクスポートが利用できない場合に、マニフェストファイルをスキャンするかどうか。詳細については、[マニフェストフォールバック](../dependency_scanning/dependency_scanning_sbom/_index.md#manifest-fallback)を参照してください。 | `DS_ENABLE_MANIFEST_FALLBACK` |
| `pipcompileLockfileFileNamePattern` | 処理対象のpip-compileロックファイルを選択するグロブパターン。このパターンはファイル名のみに一致し、ディレクトリパスには一致しません。 | `DS_PIPCOMPILE_LOCKFILE_FILE_NAME_PATTERN` |
| `pipManifestFileNamePattern` | 依存関係解決とマニフェストスキャンのために処理対象のpipマニフェストファイルを選択するグロブパターン。このパターンはファイル名のみに一致し、ディレクトリパスには一致しません。 | `DS_PIP_MANIFEST_FILE_NAME_PATTERN` |
| `enableVulnerabilityScan` | 生成されたSBOMの脆弱性分析が有効かどうか。 | `DS_ENABLE_VULNERABILITY_SCAN` |
| `apiTimeout` | 脆弱性スキャンAPIリクエストのタイムアウト（秒）。5～300の範囲で指定します。 | `DS_API_TIMEOUT` |
| `apiScanDownloadDelay` | スキャン結果をダウンロードする前の脆弱性スキャンAPIの初期遅延（秒）。1～120の範囲で指定します。 | `DS_API_SCAN_DOWNLOAD_DELAY` |
| `mavenDependencyPluginVersion` | 解決時に使用される`maven-dependency-plugin`のバージョン。 | `DS_MAVEN_DEPENDENCY_PLUGIN_VERSION` |
| `mavenArgs` | 依存関係解決中にMavenに渡される追加の引数。 | `MAVEN_ARGS` |
| `gradleCliOpts` | 依存関係解決中にGradleに渡される追加のコマンドラインオプション。 | `GRADLE_CLI_OPTS` |
| `disabledResolutionJobs` | 無効にする解決ジョブのリスト。有効な値は`MAVEN`、`GRADLE`、`PYTHON`です。デフォルトでは、利用可能なすべての解決ジョブが有効になります。 | `DS_DISABLED_RESOLUTION_JOBS` |
| `mavenResolutionImage` | Mavenの依存関係解決ジョブで使用されるイメージ。 | `DS_MAVEN_RESOLUTION_IMAGE` |
| `gradleResolutionImage` | Gradleの依存関係解決ジョブで使用されるイメージ。 | `DS_GRADLE_RESOLUTION_IMAGE` |
| `pythonResolutionImage` | Pythonの依存関係解決ジョブで使用されるイメージ。 | `DS_PYTHON_RESOLUTION_IMAGE` |
| `pipIndexUrl` | Python Package IndexのベースURL。 | `PIP_INDEX_URL` |
| `pipExtraIndexUrl` | `pipIndexUrl`に加えて使用するPythonパッケージインデックスの追加URL。 | `PIP_EXTRA_INDEX_URL` |
| `searchIgnoreHiddenDirs` | アナライザーがサポートされているファイルを検索する際に、隠しディレクトリを無視するかどうか。 | `SEARCH_IGNORE_HIDDEN_DIRS` |

たとえば、カスタマイズしたマージリクエストパイプライントリガーを使用して依存関係スキャンプロファイルを作成する場合は、次のようにします:

```graphql
mutation {
  securityScanProfileCreate(input: {
    namespaceId: "gid://gitlab/Group/123",
    scanType: DEPENDENCY_SCANNING,
    name: "Custom dependency scanning profile",
    description: "Dependency scanning profile that excludes development dependencies and scans all directories",
    triggers: [
      {
        triggerType: MERGE_REQUEST_PIPELINE,
        configuration: {
          dependencyScanning: {
            includeDevDependencies: false,
            excludedPaths: ["spec/**/*", "test/**/*"],
            maxDepth: -1,
            staticReachabilityEnabled: true
          }
        }
      }
    ]
  }) {
    scanProfile {
      id
      name
    }
    errors
  }
}
```

各トリガーに指定できる設定項目は1つだけで、プロファイルのスキャンタイプと一致している必要があります。依存関係スキャンプロファイルの場合、そのメンバーは`dependencyScanning`です。

引数の完全なリストについては、[`securityScanProfileCreate`ミューテーション](../../../api/graphql/reference/_index.md#mutationsecurityscanprofilecreate)を参照してください。

## カバレッジステータスインジケーター {#coverage-status-indicators}

システムでは、インベントリ内の視覚的なブロックを使用して、プロジェクトが保護されているかどうかを示します:

- **緑色の実線バー**: スキャナーが完全に有効化され、アクティブになっています。
- **グレー/空のバー**: スキャナーはまだ設定されていないか、有効化されていません。
- **一部のみ表示されたバー**: 一部の保護がアクティブです（例: プロファイルで利用可能な一部のトリガーは有効になっていますが、その他は無効です）。
- **ツールチップ**: カバレッジバーにカーソルを合わせると、パイプラインベースのスキャンの最終スキャン日と、該当するパイプラインのステータスが表示されます。

パイプラインベースのスキャンとは異なり、プッシュ保護はプッシュプロセス中にリアルタイムで実行されるため、最終スキャン日がありません。

## トラブルシューティング {#troubleshooting}

セキュリティ設定プロファイルを使用する際に、次の問題が発生する可能性があります。

### プッシュ保護で最終スキャン日が表示されない {#no-last-scan-date-appears-for-push-protection}

プッシュ保護はイベントベースであり、スケジュールベースではありません。これは`git push`プロセス中にシークレットをリアルタイムでインターセプトします。`push`コマンドの実行時に動作するため、パイプラインベースのスキャナーのような最終スキャン日はありません。

### スキャナーのステータスがダッシュボードではアクティブだが、インベントリのツールチップでは有効になっていない {#scanner-status-is-active-in-the-dashboard-but-not-enabled-in-inventory-tooltip}

プロジェクトに新しいプロファイルが割り当てられている一方で、レガシー設定も使用されている場合に、この問題が発生することがあります。

この問題を解決するには:

1. 現在のプロファイルの状態を最も正確に確認するには、**セキュリティ設定**ページを確認します。
1. 必要に応じて、`.gitlab-ci.yml`ファイルからレガシースキャナー設定を削除して、プロファイルベースの設定のみを使用します。

> [!note]
> インベントリのツールチップは、レガシー設定とプロファイルベースの設定の両方を組み合わせたステータスが反映されるよう改善が進められています。

### レガシー設定とプロファイルベースの設定の違いを理解する {#understanding-legacy-versus-profile-based-configuration}

レガシースキャナー設定からプロファイルベースの設定に移行する場合は、次の違いに注意してください:

- レガシー設定: スキャナーを有効にするには、YAMLファイルまたは個々のプロジェクト設定を手動で編集する必要があります。
- プロファイルベースの設定: 一元管理されたシステムを使用し、コードを変更することなく、複数のプロジェクトにデフォルトプロファイルを一度に適用できます。

管理が容易になり、プロジェクト間の一貫性も高まるため、プロファイルベースの設定をおすすめします。
