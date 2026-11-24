---
title: GitLab Runner 19.5
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
documentation_link: https://docs.gitlab.com/runner
work_item: https://gitlab.com/gitlab-org/gitlab-runner/-/issues/?milestone_title=19.5&state=closed
categories: [ GitLab Runner Core ]
level: secondary
---

本日、GitLab Runner 19.5もリリースしました。GitLab Runnerは、CI/CDジョブを実行してその結果をGitLabインスタンスに送信する、高いスケーラビリティを持つビルドエージェントです。GitLab Runnerは、GitLabに含まれるオープンソースの継続的インテグレーションサービスであるGitLab CI/CDと連携して動作します。

**新機能**

- [ヘルパーコンテナがOOMキルされた際のKubernetesエグゼキューターのエラーメッセージを改善](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39842)
- [ジョブ開始時にジョブ実行環境のCPUモデルをログに記録](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39814)

**バグ修正**

- [DockerサービスのヘルスチェックがIPv4のみのサービスでデュアルスタックネットワーク上で失敗する（最後に解決されたアドレスのみにダイヤルするため）](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39939)
- [インスタンスプレフィックスを持つRunnerおよびジョブトークンが認識されない](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39938)
- [Kubernetesエグゼキューターがポーリングのたびにページネーションなしのイベント`LIST`リクエストを送信し、高負荷クラスターでAPIのPriority and Fairnessを飽和させる](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39848)
- [Dockerエグゼキューターがビルドコンテナのみではなくサービスコンテナにも`mac_address`を適用する](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39803)
- [`RUNNER_AFTER_SCRIPT_TIMEOUT`がジョブのタイムアウトを超えた場合に5分にリセットされる](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39717)
- [SigV4署名ヘッダールールを適用するS3サーバーで`cache_archiver`がプリサインドURLに署名されていない`Content-Type`を送信するためキャッシュのアップロードが`403`で失敗する](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39701)
- [Kubernetesエグゼキューターが常に空のポッドレベルの`resources`オブジェクトを設定し、Kubernetes 1.34以降で`BestEffort` QoSの誤分類を引き起こす](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39671)
- [Step-runnerのローカルサーバーがgRPCサーバーのリッスン開始前にreadyを報告する](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39653)
- [ドキュメント化された`systemd`のグレースフルシャットダウン設定がVirtualBox、Parallels、SSHエグゼキューターの実行中のVMを強制終了する](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39563)
- [イメージにマルチ引数の`ENTRYPOINT`がある場合、`proxy_exec`がジョブを実行せずにヘルパーバイナリのヘルプを表示して終了する](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39452)
- [同一イメージの複数プラットフォームがプルされた場合にDockerエグゼキューターが`platform`パラメーターを無視する](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/38514)

すべての変更点の一覧はGitLab Runnerの[CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/19-5-stable/CHANGELOG.md)をご覧ください。
