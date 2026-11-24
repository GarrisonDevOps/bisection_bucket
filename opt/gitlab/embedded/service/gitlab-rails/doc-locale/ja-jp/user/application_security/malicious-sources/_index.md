---
stage: Application Security Testing
group: Threat Research
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 悪意のあるソースのスキャン
description: ソースコード内の既知の悪意のあるドメインへの参照を検出します。
---

{{< details >}}

- プラン: Ultimate
- 提供形態: GitLab.com
- ステータス: 実験的機能

{{< /details >}}

{{< history >}}

- GitLab 19.3で[実験](../../../policy/development_stages_support.md#experiment)として[GitLab.comに導入](https://gitlab.com/groups/gitlab-org/-/work_items/22809)されました。

{{< /history >}}

悪意のあるソースのスキャンは、polyfill.ioのサプライチェーン攻撃に関与したCDNなど、リポジトリ内の既知の悪意のある外部ドメインへの参照を検出します。各参照は、SASTの脆弱性として報告されます。

この実験の今後の方向性を決定する際の参考にするため、[イシュー634760](https://gitlab.com/gitlab-org/gitlab/-/work_items/634760)でフィードバックを共有してください。

## 悪意のあるソースのスキャンを有効にする {#turn-on-malicious-sources-scanning}

悪意のあるソースのスキャンを有効にするには、`.gitlab-ci.yml`ファイルに[悪意のあるソースのCI/CDコンポーネント](https://gitlab.com/explore/catalog/security-products/experiments/malicious-sources)を追加します:

```yaml
include:
  - component: gitlab.com/security-products/experiments/malicious-sources/malicious-sources@0.2.0
```

このコンポーネントは、`test`ステージに`malicious-sources-scan`ジョブを追加します。検出結果は、[脆弱性レポート](../vulnerability_report/_index.md)とマージリクエストに表示されます。

## 検出されるドメイン {#detected-domains}

悪意のあるソースのスキャンは、重大度が`Critical`のこれらのドメインへの参照を検出します:

- `bootcdn.net`
- `bootcss.com`と`cdn.bootcss.com`
- `polyfill.com`
- `polyfill.io`と`cdn.polyfill.io`
- `staticfile.net`と`cdn.staticfile.net`
- `staticfile.org`と`cdn.staticfile.org`
- `unionadjs.com`

このアナライザーは、`https://`、`http://`、およびプロトコル相対（`//`）参照を大文字と小文字を区別せずに照合します。

## パスを除外する {#exclude-paths}

ファイルとディレクトリをスキップするには、`SAST_EXCLUDED_PATHS`にgitignore形式のパターンをコンマ区切りのリストとして設定します。`.git`ディレクトリは常に除外されます。

```yaml
variables:
  SAST_EXCLUDED_PATHS: "node_modules, vendor, **/*.min.js"
```

## カスタムルールの追加 {#add-custom-rules}

他のドメインを検出するには、`MALICIOUS_SOURCES_CUSTOM_RULES`にルールのYAMLリストを設定します。カスタムルールは、ビルトインルールに追加されます。

```yaml
variables:
  MALICIOUS_SOURCES_CUSTOM_RULES: |
    - rule_id: malicious.example.test
      substring: //malicious.example.test
      severity: High
      title: "Malicious CDN: malicious.example.test"
      description: "Known malicious CDN observed in supply chain attacks."
```

| フィールド              | 必須 | 説明 |
|--------------------|----------|-------------|
| `rule_id`          | はい      | 一意のID。ビルトインルールを上書きするには、ルールのドメインをIDとして使用します。 |
| `substring`        | はい      | 各行で照合するリテラルテキスト。正規表現はサポートされていません。 |
| `severity`         | はい      | `Info`、`Low`、`Medium`、`High`、`Critical`のいずれかを指定します。 |
| `title`            | はい      | 検出結果に表示される名前。 |
| `description`      | はい      | 脆弱性レポートに表示される説明。 |
| `case_insensitive` | いいえ       | `true`の場合、大文字と小文字を区別せずに照合します。デフォルトは`false`です。 |
| `disabled`         | いいえ       | `true`の場合、ルールが削除されます。デフォルトは`false`です。 |

ビルトインルールを無効にするには、そのドメインに`disabled: true`を設定します:

```yaml
variables:
  MALICIOUS_SOURCES_CUSTOM_RULES: |
    - rule_id: cdn.polyfill.io
      disabled: true
```

YAMLが無効な場合、スキャンはエラーで失敗します。
