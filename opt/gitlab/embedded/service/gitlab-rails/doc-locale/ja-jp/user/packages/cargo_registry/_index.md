---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: パッケージレジストリのCargoクレート
---

{{< details >}}

- プラン: Free、Premium、Ultimate
- 提供形態: GitLab.com、GitLab Self-Managed、GitLab Dedicated
- ステータス: 実験的機能

{{< /details >}}

{{< history >}}

- GitLab 19.5で`package_registry_cargo_support`という名前の[機能フラグを使用して](../../../administration/feature_flags/_index.md) [導入](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254282)されました。デフォルトでは無効になっています。

{{< /history >}}

> [!flag]
> この機能の利用可否は、機能フラグによって制御されます。詳細については、履歴を参照してください。この機能はテストには利用できますが、本番環境での使用には適していません。

Cargoクレート（Rustパッケージ）をプロジェクトのパッケージレジストリに公開できます。その後、Cargoを使用してインストールできます。

この機能の開発の詳細については、[issue 33060](https://gitlab.com/gitlab-org/gitlab/-/issues/33060)を参照してください。

Cargoレジストリはプロジェクトでのみ利用できます。グループレジストリやインスタンスレジストリはありません。GitLabはスパースインデックスプロトコルのみをサポートしています。

## パッケージレジストリに対して認証する {#authenticate-to-the-package-registry}

パッケージレジストリを操作する前に、認証する必要があります。

1. プロジェクトで、`.cargo/config.toml`ファイルを作成または編集します。
1. レジストリを追加します:

   ```toml
   [registries.gitlab]
   index = "sparse+https://<gitlab.example.com>/api/v4/projects/<project_id>/packages/cargo/"
   credential-provider = "cargo:token"
   ```

   次の値を置き換えます:

   - `<gitlab.example.com>`: GitLabインスタンスのホスト名。GitLab.comの場合は、`gitlab.com`を使用します。
   - `<project_id>`: プロジェクトID。

   `index` URLの末尾のスラッシュは必須です。

   `[registries.gitlab]`内の`gitlab`キーはレジストリ名です。これはローカルエイリアスであり、任意の名前を選択できます。このページの`--registry gitlab`コマンドはこの名前を使用します。

1. 環境変数にトークンを設定します:

   ```shell
   export CARGO_REGISTRIES_GITLAB_TOKEN="Bearer <token>"
   ```

   変数名は`CARGO_REGISTRIES_<NAME>_TOKEN`です。`<NAME>`は大文字のレジストリ名で、`-`は`_`に置き換えられます。たとえば、`my-registry`という名前のレジストリの場合は、`CARGO_REGISTRIES_MY_REGISTRY_TOKEN`を使用します。

トークンを設定ファイルに保存しないでください。

| トークン | インストールに必要なスコープ | 公開に必要なスコープ |
|-------|------------------|------------------|
| [パーソナルアクセストークン](../../profile/personal_access_tokens.md) | `api` | `api` |
| [プロジェクトアクセストークン](../../project/settings/project_access_tokens.md) | `api` | `api` |
| [詳細権限パーソナルアクセストークン](../../../auth/tokens/fine_grained_access_tokens.md) | `Package: Read` | `Package: Read`と`Package: Create` |
| [デプロイトークン](../../project/deploy_tokens/_index.md) | `read_package_registry` | `read_package_registry`と`write_package_registry` |
| [CI/CDジョブトークン](../../../ci/jobs/ci_job_token.md) | 該当なし | 該当なし |

パブリックプロジェクトからのクレートのインストールは、トークンなしで誰でも行えます。プライベートプロジェクトおよび内部プロジェクトにはトークンが必要です。

## クレートを公開する {#publish-a-crate}

前提条件: 

- [パッケージレジストリに認証](#authenticate-to-the-package-registry)する必要があります。
- デベロッパーロール以上が必要です。
- クレートは10MB以下である必要があります。

クレートを公開するには:

1. 次のコマンドを実行します:

   ```shell
   cargo publish --registry gitlab
   ```

   GitLabはバックグラウンドでクレートを処理します。処理が完了すると、クレートはレジストリインデックスと**デプロイ** > **パッケージレジストリ**ページに表示されます。

1. オプション。クレートが誤ってcrates.ioに公開されるのを防ぐには、`Cargo.toml`ファイルの`[package]`セクションに`publish`キーを追加します:

   ```toml
   [package]
   name = "my-crate"
   version = "0.1.0"
   publish = ["gitlab"]
   ```

### GitLab CI/CDを使用して公開する {#publish-with-gitlab-cicd}

CI/CDジョブトークンを使用して、CI/CDジョブからクレートを公開できます。トークンや設定ファイルを作成する必要はありません。

`.gitlab-ci.yml`ファイルに以下を追加します:

```yaml
publish:
  image: rust:1
  variables:
    CARGO_REGISTRIES_GITLAB_INDEX: "sparse+${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/cargo/"
    CARGO_REGISTRIES_GITLAB_TOKEN: "Bearer ${CI_JOB_TOKEN}"
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - cargo publish --registry gitlab
```

### クレート名とバージョン {#crate-names-and-versions}

クレート名は次の条件を満たす必要があります:

- 文字で始める。
- 64文字以下にする。
- 文字、数字、ハイフン（`-`）、アンダースコア（`_`）のみを含める。

クレート名は大文字と小文字を区別せず、ハイフンとアンダースコアは同等として扱われます。たとえば、`my_crate`と`My-Crate`は同じクレートを指します。

バージョンは[セマンティックバージョン](https://semver.org/)である必要があります。

既存のバージョンを公開することはできません。Cargoは、リクエストがGitLabに到達する前に停止します。リクエストがGitLabに到達した場合、GitLabは`Package already exists`というメッセージとともに`400`エラーを返します。プロジェクトの重複パッケージ設定はCargoには適用されません。

[パッケージ保護ルール](../package_registry/package_protection_rules.md)はCargoクレートに適用されます。ルールがクレート名を保護している場合、GitLabは`403`エラーを返します。Cargoはこのエラーを出力します:

```plaintext
the remote server responded with an error (status 403 Forbidden): Package protected.
```

## クレートをインストールする {#install-a-crate}

前提条件: 

- [パッケージレジストリに認証](#authenticate-to-the-package-registry)する必要があります。

クレートをインストールするには、次のいずれかの方法を使用します:

{{< tabs >}}

{{< tab title="マニフェストで" >}}

`Cargo.toml`ファイルで、`[dependencies]`セクションにクレートを追加します:

```toml
[dependencies]
my-crate = { version = "0.1", registry = "gitlab" }
```

{{< /tab >}}

{{< tab title="`cargo add`を使用" >}}

以下を実行します。

```shell
cargo add my-crate --registry gitlab
```

{{< /tab >}}

{{< tab title="`cargo install`を使用" >}}

バイナリを含むクレートをインストールするには、以下を実行します:

```shell
cargo install my-crate --registry gitlab
```

{{< /tab >}}

{{< /tabs >}}

crates.ioのクレートは、プロジェクトのレジストリのクレートと並行して引き続き動作します。

## クレートを削除する {#delete-a-crate}

前提条件: 

- メンテナーまたはオーナーのロールを持っている必要があります。

パッケージを削除する前に、[関連するセキュリティリスク](../package_registry/supported_functionality.md#deleting-packages)を理解していることを確認してください。

パッケージを削除するには、次のいずれかの方法があります:

- [UIを使用する](../package_registry/reduce_package_registry_storage.md#delete-a-package)。
- [APIを使用する](../../../api/packages.md#delete-a-project-package)。

## サポートされていないCargoコマンド {#unsupported-cargo-commands}

GitLabは次のコマンドをサポートしていません:

- `cargo yank`
- `cargo search`
- `cargo owner`

バージョンを削除するには、パッケージを削除します。

## 関連トピック {#related-topics}

- [The Cargo Book: Registries](https://doc.rust-lang.org/cargo/reference/registries.html)
