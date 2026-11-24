---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLabプロジェクトのGit属性を定義して、ファイル処理、表示、ロック、ストレージのオプションを設定します。
title: Git属性
---

{{< details >}}

- プラン: Free、Premium、Ultimate
- 提供形態: GitLab.com、GitLab Self-Managed、GitLab Dedicated

{{< /details >}}

GitLabは、リポジトリのルートディレクトリにある`.gitattributes`ファイルでカスタムGit属性の定義をサポートします。`.gitattributes`ファイルを使用して、ファイル処理と表示に対する変更を宣言します。以下はその例です:

- 差分内の[生成されたファイルを折りたたむ](../../merge_requests/changes.md#collapse-generated-files)。
- [カスタムマージドライバー](#custom-merge-drivers)を作成します。
- [排他的なロックファイル](../../file_lock.md)を作成して、ファイルを読み取り専用としてマークします。
- 差分内の[構文ハイライト](highlighting.md)を変更します。
- バイナリファイルの処理を[Git LFS](../../../../topics/git/lfs/_index.md)で宣言します。
- [リポジトリで使用されている言語](../_index.md#add-repository-languages)を宣言します。

## エンコード要件 {#encoding-requirements}

`.gitattributes`ファイルはUTF-8でエンコードされている必要があり、バイトオーダーマークを含んでいてはいけません。異なるエンコードが使用されている場合、ファイルの内容は無視されます。

## 混在するファイルエンコードのサポート {#support-for-mixed-file-encodings}

GitLabはファイルのエンコードを自動的に検出しますが、検出器が異なるタイプ（`ISO-8859-1`など）に確信がない限り、デフォルトでUTF-8になります。不正確なエンコード検出は、UTF-8以外のエンコードのアクセント付き文字のように、テキストに一部の文字が表示されない原因となる可能性があります。

Gitには、この不測の事態を処理するための組み込みサポートがあり、指定されたエンコードとUTF-8の間でリポジトリ自体のファイルを自動的に変換します。`.gitattributes`ファイルで、`working-tree-encoding`属性を使用して混在するファイルエンコードのサポートを設定します。

例: 

```plaintext
*.xhtml text working-tree-encoding=ISO-8859-1
```

この設定例では、Gitはリポジトリ内のすべての`.xhtml`ファイルをISO-8859-1エンコードでローカルツリーに保持しますが、リポジトリへのコミット時にはUTF-8との間で変換します。GitLabは正しくエンコードされたUTF-8のみを認識するため、ファイルを正確にレンダリングします。

この設定を既存のリポジトリに適用する場合、ローカルコピーには正しいエンコードがあるがリポジトリにはない場合、ファイルを更新して再コミットする必要がある場合があります。これは、`git add --renormalize .`を実行することでリポジトリ全体に対して実行できます。

詳細については、[working-tree-encoding](https://git-scm.com/docs/gitattributes#_working_tree_encoding)を参照してください。

## 構文ハイライト {#syntax-highlighting}

`.gitattributes`ファイルは、ファイルと差分の構文ハイライトに使用する言語を定義するために使用できます。詳細については、[構文ハイライト](highlighting.md)を参照してください。

## カスタムマージドライバー {#custom-merge-drivers}

{{< details >}}

- プラン: Free、Premium、Ultimate
- 提供形態: GitLab Self-Managed、GitLab Dedicated

{{< /details >}}

GitLab Self-Managedの管理者は、GitLab設定ファイルで[カスタムマージドライバー](https://git-scm.com/docs/gitattributes#_defining_a_custom_merge_driver)を定義し、そのカスタムマージドライバーをGit `.gitattributes`ファイルで使用できます。カスタムマージドライバーはGitLab.comではサポートされていません。

カスタムマージドライバーは、競合解決を高度に制御できるGit機能です。カスタムマージドライバーは、非自明な[マージコンフリクト](../../merge_requests/conflicts.md)の場合にのみ実行されます。そのため、一部のファイルがマージされるのを防ぐ信頼できる方法ではありません。

### カスタムマージドライバーを設定する {#configure-a-custom-merge-driver}

次の例は、GitLabでカスタムマージドライバーを定義して使用する方法を示しています。

カスタムマージドライバーの設定方法は、インストールタイプによって異なります。

{{< tabs >}}

{{< tab title="Linuxパッケージ（Omnibus）" >}}

1. `/etc/gitlab/gitlab.rb`を編集します。
1. 次のような設定を追加します:

   ```ruby
   gitaly['configuration'] = {
     # ...
     git: {
       # ...
       config: [
         # ...
         { key: "merge.foo.driver", value: "true" },
       ],
     },
   }
   ```

{{< /tab >}}

{{< tab title="自己コンパイル（ソース）" >}}

1. `gitaly.toml`を編集します。
1. 次のような設定を追加します:

   ```toml
   [[git.config]]
   key = "merge.foo.driver"
   value = "true"
   ```

{{< /tab >}}

{{< /tabs >}}

この例では、マージ中にGitは`driver`の値を実行するコマンドとして使用します。この例では[`true`](https://man7.org/linux/man-pages/man1/true.1.html)を引数なしで使用しているため、常にゼロ以外のリターンコードを返します。これは、`.gitattributes`で指定されたファイルに対しては、マージは何も実行しないことを意味します。

独自のマージドライバーを使用するには、`driver`の値を実行可能ファイルにポイントするように置き換えます。このコマンドがどのように実行されるかの詳細については、[カスタムマージドライバー](https://git-scm.com/docs/gitattributes#_defining_a_custom_merge_driver)に関するGitドキュメントを参照してください。

### カスタムマージドライバーが適用されるファイルを`.gitattributes`を使用して設定する {#use-gitattributes-to-set-files-custom-merge-driver-applies-to}

`.gitattributes`ファイルで、カスタムマージドライバーで使用したいファイルのパスを設定できます。例: 

```plaintext
config/* merge=foo
```

この場合、`config/`フォルダーの下にあるすべてのファイルは、GitLab設定で定義された`foo`という名前のカスタムマージドライバーを使用します。

## リソース {#resources}

- [Git属性](https://git-scm.com/docs/gitattributes)に関する公式Gitドキュメント
