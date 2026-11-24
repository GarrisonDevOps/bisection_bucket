---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Cron
description: 작업을 실행할 시간을 예약합니다.
---

Cron 구문은 작업을 실행할 시간을 예약하는 데 사용됩니다.

[파이프라인 일정](../../ci/pipelines/schedules.md)을 생성하거나 [배포 동결](../../user/project/releases/_index.md#prevent-unintentional-releases-by-setting-a-deploy-freeze)을 설정하여 의도하지 않은 릴리스를 방지하기 위해 Cron 구문 문자열을 사용해야 할 수 있습니다.

## Cron 구문 {#cron-syntax}

Cron 스케줄링은 공백으로 구분된 5개의 숫자로 이루어진 일련의 숫자를 사용합니다:

```plaintext
# ┌───────────── minute (0 - 59)
# │ ┌───────────── hour (0 - 23)
# │ │ ┌───────────── day of the month (1 - 31)
# │ │ │ ┌───────────── month (1 - 12)
# │ │ │ │ ┌───────────── day of the week (0 - 6) (Sunday to Saturday)
# │ │ │ │ │
# │ │ │ │ │
# │ │ │ │ │
# * * * * * <command to execute>
```

(출처: [Wikipedia](https://en.wikipedia.org/wiki/Cron))

Cron 구문에서 별표(`*`)는 '매번'을 의미하므로 다음 Cron 문자열은 유효합니다:

- 매시간 0분에 실행: `0 * * * *`
- 매일 자정에 실행: `0 0 * * *`
- 매주 일요일 자정에 실행: `0 0 * * 0`
- 매월 1일 자정에 실행: `0 0 1 * *`
- 매월 22일에 실행: `0 0 22 * *`
- 매년 1월 1일 자정에 실행: `0 0 1 1 *`
- 매월 1일과 15일 오전 3시에 2회 실행: `0 3 1,15 * *`

완전한 Cron 설명서는 [crontab(5) Linux 설명서 페이지](https://man7.org/linux/man-pages/man5/crontab.5.html)를 참조하세요. 이 설명서는 Linux 또는 macOS 터미널에 `man 5 crontab`를 입력하여 오프라인으로 접근할 수 있습니다.

또한 GitLab은 [`fugit`](#how-gitlab-parses-cron-syntax-strings)를 사용하며, `#` 및 `%` 구문을 허용합니다. 이 구문은 모든 Cron 테스터에서 작동하지 않을 수 있습니다:

- 매월 두 번째 월요일에 실행: `0 0 * * 1#2`. 이 구문은 [`fugit` 해시 확장](https://github.com/floraison/fugit#the-hash-extension)에서 제공합니다.
- 격주 일요일 09:00에 실행: `0 9 * * sun%2`. 이 구문은 [`fugit` 모듈로 확장](https://github.com/floraison/fugit#the-modulo-extension)에서 제공합니다.

## Cron 예제 {#cron-examples}

```plaintext
# Run at 7:00pm every day:
0 19 * * *

# Run every minute on the 3rd of June:
* * 3 6 *

# Run at 06:30 every Friday:
30 6 * * 5
```

Cron 스케줄을 작성하는 방법에 대한 더 많은 예제는 [crontab.guru](https://crontab.guru/examples.html)에서 찾을 수 있습니다.

## GitLab이 Cron 구문 문자열을 구문 분석하는 방법 {#how-gitlab-parses-cron-syntax-strings}

GitLab은 서버에서 Cron 구문 문자열을 구문 분석하기 위해 [`fugit`](https://github.com/floraison/fugit)를 사용하고 브라우저에서 Cron 구문을 확인하기 위해 [cron-validator](https://github.com/GuillaumeRochat/cron-validator)를 사용합니다. GitLab은 브라우저에서 Cron을 사람이 읽을 수 있는 문자열로 변환하기 위해 [`cRonstrue`](https://github.com/bradymholt/cRonstrue)를 사용합니다.
