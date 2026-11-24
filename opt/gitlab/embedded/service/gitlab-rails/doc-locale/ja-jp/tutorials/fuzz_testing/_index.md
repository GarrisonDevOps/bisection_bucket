---
stage: Application Security Testing
group: Dynamic Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments
title: 'チュートリアル: GitLabでファズテストを実行する（非推奨）'
---

<!--- start_remove The following content will be removed on remove_date: '2026-08-15' -->

{{< details >}}

- プラン: Ultimate
- 提供形態: GitLab.com、GitLab Self-Managed、GitLab Dedicated

{{< /details >}}

{{< alert type="warning" >}}

カバレッジガイドファズテストはGitLab 18.0で[非推奨](https://gitlab.com/gitlab-org/gitlab/-/issues/517841)となり、19.0で削除される予定です。これは破壊的な変更です。

{{< /alert >}}

<!-- vale gitlab_base.FutureTense = NO -->

[カバレッジガイドファズテスト](../../user/application_security/coverage_fuzzing/_index.md#coverage-guided-fuzz-testing-process)は、予期しない不正な形式データやランダムなデータをアプリケーションに送信し、不安定な動作やクラッシュがないか監視します。

これにより、他の品質保証プロセスでは見逃される可能性のあるバグや潜在的なセキュリティ上の問題を検出できます。

ファズテストは、他のセキュリティスキャナーや独自のテストプロセスに追加して使用する必要があります。GitLab CI/CDを使用している場合は、継続的インテグレーションとデリバリーワークフローの一部としてファズテストを実行できます。

このチュートリアルでJavaScriptを使用してカバレッジガイドファズテストをセットアップ、構成、および実行するには、次の手順を実行します:

1. ファズテストを実行するプロジェクトを作成するために、[プロジェクトテンプレートをフォークする](#fork-the-project-template)。
1. [ファズターゲットを作成する](#create-the-fuzz-targets)。
1. [フォークしたプロジェクトでカバレッジガイドファズテストを有効にする](#enable-coverage-guided-fuzz-testing)。
1. セキュリティの脆弱性を特定するために[ファズテストを実行する](#run-the-fuzz-test)。
1. [ファズテストで特定された脆弱性を修正する](#fix-the-vulnerabilities)。

## プロジェクトテンプレートをフォークする {#fork-the-project-template}

まず、ファズテストを試すプロジェクトを作成するには、`fuzz-testing`プロジェクトテンプレートをフォークする必要があります:

1. [`fuzz-testing`プロジェクトテンプレート](https://gitlab.com/gitlab-org/tutorial-project-templates/fuzz-testing)を開きます。
1. [プロジェクトテンプレートをフォークする](../../user/project/repository/forking_workflow.md)。
1. プロジェクトテンプレートをフォークする場合:
   - フォークされたプロジェクトに`fuzz-testing-demo`という名前を付けます。
   - 適切な[ネームスペース](../../user/namespace/_index.md)を選択します。
   - [プロジェクトの表示レベル](../../user/public_access.md)を**プライベート**に設定します。

正常に`fuzz-testing`プロジェクトテンプレートをフォークしました。ファズテストを開始する前に、プロジェクトテンプレートとフォークの関係を削除します:

1. 左側のサイドバーで、**設定** > **一般**を選択します。
1. **高度な設定**を展開します。
1. **フォークの関係を削除**セクションで、**フォークの関係を削除**を選択します。プロンプトが表示されたら、プロジェクトの名前を入力します。

プロジェクトの準備が完了し、ファズテストを作成できるようになりました。次に、ファズターゲットを作成します。

## ファズターゲットを作成する {#create-the-fuzz-targets}

ファズテストのプロジェクトができたので、ファズターゲットを作成します。ファズターゲットは、入力が与えられたときに、テスト対象のアプリケーションを呼び出す関数またはプログラムです。

このチュートリアルでは、ファズターゲットは、パラメータとしてランダムなバッファを使用して、`my-tools.js`ファイルの関数を呼び出す。

2つのファズターゲットファイルを作成するには:

1. 左側のサイドバーで、**検索または移動先**を選択し、`fuzz-testing-demo`プロジェクトを見つけます。
1. プロジェクトのルートディレクトリにファイルを作成します。
1. ファイルに`fuzz-sayhello.js`という名前を付け、次のコードを追加します:

   ```javascript
   let tools = require('./my-tools')

   function fuzz(buf) {
     const text = buf.toString()
     tools.sayHello(text)
   }

   module.exports = {
     fuzz
   }
   ```

   このコードは、`fuzz-testing-demo/fuzzers/fuzz-sayhello.js`プロジェクトファイルからコピーすることもできます。

1. **Target Branch**（ターゲットブランチ）に`add-fuzz-test`という名前を付け、記述的なコミットメッセージを作成します。
   - **Start a new merge request with these changes**（これらの変更で新しいマージリクエストを開始する）チェックボックスはまだ選択しないでください。
1. **変更をコミットする**を選択します。
1. プロジェクトのルートディレクトリに戻ります。
1. `add-fuzz-test`ブランチにいることを確認してください。
1. `fuzz-readme.js`という名前の2番目のファイルを作成し、次のコードを追加します:

   ```javascript
   let tools = require('./my-tools')
   function fuzz(buf) {
       const text = buf.toString()
       tools.readmeContent(text)
   }
   module.exports = {
       fuzz
   }
   ```

   このコードは、`fuzz-testing-demo/fuzzers/fuzz-readme.js`プロジェクトファイルからコピーすることもできます。

1. 記述的なコミットメッセージを作成します。
1. **Target Branch**（ターゲットブランチ）が`add-fuzz-test`であることを確認してください。
1. **変更をコミットする**を選択します。

これで、テスト対象のアプリケーションを呼び出すことができる2つのファズターゲットができました。次に、ファズテストを有効にします。

## カバレッジガイドファズテストを有効にします。 {#enable-coverage-guided-fuzz-testing}

カバレッジガイドファズテストを有効にするには、2つのファズターゲットでファズテストを実行する`gitlab-cov-fuzz`コマンドラインインターフェースを実行するCI/CDパイプラインを作成します。

パイプラインファイルを作成するには:

1. `add-fuzz-test`ブランチにいることを確認してください。
1. `fuzz-testing-demo`プロジェクトのルートディレクトリに、新しいファイルを作成します。
1. ファイルに`.gitlab-ci.yml`という名前を付け、次のコードを追加します:

   ```yaml
   default:
     image: node:18

   stages:
     - fuzz

   include:
     - template: Coverage-Fuzzing.gitlab-ci.yml

   readme_fuzz_target:
     extends: .fuzz_base
     tags: [saas-linux-large-amd64] # Optional
     variables:
       COVFUZZ_ADDITIONAL_ARGS: '--fuzzTime=60'
     script:
       - npm config set @gitlab-org:registry https://gitlab.com/api/v4/packages/npm/ && npm i -g @gitlab-org/jsfuzz
       - ./gitlab-cov-fuzz run --engine jsfuzz -- fuzz-readme.js

   hello_fuzzing_target:
     extends: .fuzz_base
     tags: [saas-linux-large-amd64] # Optional
     variables:
       COVFUZZ_ADDITIONAL_ARGS: '--fuzzTime=60'
     script:
       - npm config set @gitlab-org:registry https://gitlab.com/api/v4/packages/npm/ && npm i -g @gitlab-org/jsfuzz
       - ./gitlab-cov-fuzz run --engine jsfuzz -- fuzz-sayhello.js
   ```

   この手順では、パイプラインに次が追加されます:
   - テンプレートを使用する`fuzz`ステージ。
   - 2つのジョブ、`readme_fuzz_target`と`hello_fuzzing_target`。各ジョブは`jsfuzz`エンジンを使用して実行され、未処理の例外をクラッシュとしてレポートします。

   このコードは、`fuzz-testing-demo/fuzzers/fuzzers.yml`プロジェクトファイルからコピーすることもできます。

1. 記述的なコミットメッセージを作成します。
1. **Target Branch**（ターゲットブランチ）が`add-fuzz-test`であることを確認してください。
1. **変更をコミットする**を選択します。

カバレッジガイドファズテストが正常に有効になりました。次に、作成したパイプラインを使用してファズテストを実行します。

## ファズテストの実行 {#run-the-fuzz-test}

ファズテストを実行するには:

1. 左側のサイドバーで、**コード** > **マージリクエスト**を選択します。
1. **新しいマージリクエスト**を選択します。
1. **ソースブランチ**セクションで、`add-fuzz-test`ブランチを選択します。
1. **ターゲットブランチ**セクションで、ネームスペースと`main`ブランチが選択されていることを確認します。
1. **ブランチを比較して続行する**を選択します。
1. [マージリクエストを作成する](../../user/project/merge_requests/creating_merge_requests.md)。

マージリクエストを作成すると、ファズテストを実行する新しいパイプラインがトリガーされます。パイプラインの実行が終了すると、マージリクエストページにセキュリティの脆弱性アラートが表示されます。

各脆弱性の詳細を表示するには、個々の**Uncaught-exception**（Uncaught-exception）リンクを選択します。

ファズテストが正常に実行され、修正する脆弱性が特定されました。

## 脆弱性を修正する {#fix-the-vulnerabilities}

ファズテストで2つのセキュリティ脆弱性が特定されました。これらの脆弱性を修正するには、`my-tools.js`ライブラリを使用します。

`my-tools.js`ファイルを作成するには、次のようにします:

1. プロジェクトの`add-fuzz-test`ブランチにいることを確認してください。
1. プロジェクトのルートディレクトリに移動し、`my-tools.js`ファイルを開きます。
1. このファイルの内容を次のコードに置き換えます:

   ```javascript
   const fs = require('fs')

   function sayHello(name) {
     if(name.includes("z")) {
       //throw new Error("😡 error name: " + name)
       console.log("😡 error name: " + name)
     } else {
       return "😀 hello " + name
     }
   }

   function readmeContent(name) {

     let fileName = name => {
       if(name.includes("w")) {
         return "./README.txt"
       } else {
         return "./README.md"
       }
     }

     //const data = fs.readFileSync(fileName(name), 'utf8')
     try {
       const data = fs.readFileSync(fileName(name), 'utf8')
       return data
     } catch (err) {
       console.error(err.message)
       return ""
     }

   }

   module.exports = {
     sayHello, readmeContent
   }
   ```

   このコードは、`fuzz-testing-demo/javascript/my-tools.js`プロジェクトファイルからコピーすることもできます。

1. **変更をコミットする**を選択します。これにより、別のファズテストを実行するために別のパイプラインがトリガーされます。
1. パイプラインが終了したら、マージリクエストの**概要**ページを確認します。セキュリティスキャンで、新しい潜在的な脆弱性が検出されなかったことがわかります。
1. 変更をマージします。

おめでとうございます。ファズテストが正常に実行され、特定されたセキュリティ脆弱性を修正しました。

詳細については、[カバレッジガイドファズテスト](../../user/application_security/coverage_fuzzing/_index.md)を参照してください。

<!--- end_remove -->
