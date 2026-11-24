---
stage: Security Governance
group: Security Controls
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: セキュリティインベントリ
description: グループレベルでのアセット、スキャナーのカバレッジ、脆弱性の可視化。
---

{{< details >}}

- プラン: Ultimate
- 提供形態: GitLab.com、GitLab Self-Managed、GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.2で`security_inventory_dashboard`フラグとともに[ベータ版](../../../policy/development_stages_support.md)として[導入](https://gitlab.com/groups/gitlab-org/-/epics/16484)されました。デフォルトでは有効になっています。
- GitLab 18.9で[一般提供](https://gitlab.com/gitlab-org/gitlab/-/work_items/588619)になりました。機能フラグ`security_inventory_dashboard`は削除されました。
- GitLab 19.2で検出されなくなった脆弱性を除外するように脆弱性の件数が[変更](https://gitlab.com/gitlab-org/gitlab/-/work_items/600455)され、セキュリティインベントリとセキュリティダッシュボードの整合性が確保されました。

{{< /history >}}

セキュリティインベントリを使用すると、保護が必要なアセットを可視化し、セキュリティを強化するために必要な対策を把握できます。セキュリティ分野では、「見えないものは保護できない」とよく言われます。セキュリティインベントリは、組織のトップレベルグループのセキュリティ対策状況を可視化し、カバレッジのギャップを特定しやすくして、リスクに基づいて効率的に優先順位を決められるようにします。

セキュリティインベントリには、次の情報が表示されます:

- グループ、サブグループ、プロジェクト。
- スキャナーの有効化の方法にかかわらず、各プロジェクトのセキュリティスキャナーのカバレッジ。ツールのカバレッジには、デフォルトブランチの最新パイプラインにおけるスキャンステータスが反映されます。セキュリティスキャナーには以下が含まれます:
  - 静的アプリケーションセキュリティテスト（SAST）
  - 依存関係スキャン
  - コンテナスキャン
  - シークレット検出
  - 動的アプリケーションセキュリティテスト（DAST）
  - Infrastructure as Code（IaC）スキャン
- 各グループまたはプロジェクトにおける脆弱性の件数。重大度別に並べ替えて表示されます。検出されなくなった脆弱性は件数に含まれません。

セキュリティインベントリの開発状況は、[エピック16939](https://gitlab.com/groups/gitlab-org/-/work_items/16939)で確認できます。この機能の開発は現在も進められています。[フィードバック](https://gitlab.com/gitlab-org/gitlab/-/issues/553062)をお寄せください。

## セキュリティインベントリを表示する {#view-the-security-inventory}

前提条件: 

- セキュリティインベントリを表示するには、グループのセキュリティマネージャー、デベロッパー、メンテナー、オーナーのいずれかのロールが必要です。

セキュリティインベントリを表示するには:

1. 上部のバーで、**検索または移動先**を選択して、グループを見つけます。
1. 左側のサイドバーで、**セキュリティ** > **セキュリティインベントリ**を選択します。
1. 次のいずれかのアクションを実行します:
   - グループのサブグループ、プロジェクト、セキュリティアセットを表示するには、そのグループを選択します。
   - グループまたはプロジェクトのスキャナーのカバレッジを表示するには、そのグループまたはプロジェクトを検索します。

## スキャナーカバレッジ {#scanner-coverage}

{{< history >}}

- GitLab 19.0で無効ステータスが[導入](https://gitlab.com/gitlab-org/gitlab/-/work_items/596022)されました。

{{< /history >}}

デフォルトブランチのパイプラインが完了すると、セキュリティスキャナーのステータスが評価されます。各セキュリティスキャナーには、プロジェクトまたはグループごとに、次のいずれかのカバレッジステータスが表示されます:

- **有効ではない**: スキャナーが設定されていません。
- **有効**: スキャナーが設定され、正常に完了しています。
- **失敗**: スキャナーは実行されましたが、正常に完了しませんでした。
- **無効**: 以前に有効になっていたスキャナーが、直近3回のパイプラインで一度も実行されていません。

## セキュリティインベントリ内のプロジェクトをフィルタリングする {#filter-projects-in-the-security-inventory}

{{< history >}}

- GitLab 18.5で`security_inventory_filtering`[機能フラグ](../../../administration/feature_flags/_index.md)とともに[導入](https://gitlab.com/gitlab-org/gitlab/-/issues/552224)されました。デフォルトでは有効になっています。
- 機能フラグ`security_inventory_filtering`はGitLab 19.4で削除されました。
- URLでのフィルター保持機能は、GitLab 19.5で[導入されました](https://gitlab.com/gitlab-org/gitlab/-/issues/580024)。

{{< /history >}}

セキュリティインベントリ内のプロジェクトをフィルタリングして、特定の対象領域に絞り込むことができます。次のフィルターを使用できます:

- **脆弱性の件数**: 検出された脆弱性の件数に基づいてプロジェクトをフィルタリングします。たとえば、`critical vulnerabilities ≥ 10`のプロジェクトを表示できます。
- **ツールカバレッジ**: セキュリティアナライザーのステータス（**有効**、**有効ではない**、**失敗**など）でプロジェクトをフィルタリングします。たとえば、`Advanced SAST = enabled`のプロジェクトを表示できます。
- **プロジェクト名**: 名前で特定のプロジェクトを検索します。

これらのフィルターを使用すると、大規模なインベントリで結果を絞り込み、早急な対応が必要なプロジェクトを特定しやすくなります。

URLには、適用したフィルターが保持されます。ブラウザからURLをコピーすることで、フィルタリングされたビューを共有またはブックマークできます。

## 関連トピック {#related-topics}

- [セキュリティダッシュボード](../security_dashboard/_index.md)
- [脆弱性レポート](../vulnerability_report/_index.md)
- GraphQLリファレンス:
  - [AnalyzerGroupStatusType](../../../api/graphql/reference/_index.md#analyzergroupstatustype) \- グループとそのサブグループにおけるアナライザーの各ステータスの件数。
  - [AnalyzerProjectStatusType](../../../api/graphql/reference/_index.md#analyzerprojectstatustype) \- プロジェクトのアナライザーのステータス（成功/失敗）。
  - [VulnerabilityNamespaceStatisticType](../../../api/graphql/reference/_index.md#vulnerabilitynamespacestatistictype) \- グループとそのサブグループにおける各重大度の脆弱性の件数。
  - [VulnerabilityStatisticType](../../../api/graphql/reference/_index.md#vulnerabilitystatistictype) \- プロジェクトにおける各重大度の脆弱性の件数。

## トラブルシューティング {#troubleshooting}

セキュリティインベントリを使用していると、次の問題が発生する場合があります:

### セキュリティインベントリのメニュー項目が表示されない {#security-inventory-menu-item-missing}

一部のユーザーには、**セキュリティインベントリ**のメニュー項目にアクセスするために必要な権限がありません。このメニュー項目は、認証済みユーザーがセキュリティマネージャー、デベロッパー、メンテナー、オーナーのいずれかのロールを持つグループに対してのみ表示されます。
