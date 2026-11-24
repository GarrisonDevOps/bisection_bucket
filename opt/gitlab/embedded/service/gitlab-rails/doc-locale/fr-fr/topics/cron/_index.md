---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Cron
description: "Planifiez l'exécution des jobs."
---

La syntaxe Cron est utilisée pour planifier l'exécution des jobs.

Vous devrez peut-être utiliser une chaîne de syntaxe cron pour créer une [planification de pipeline](../../ci/pipelines/schedules.md), ou pour empêcher les releases non intentionnelles en configurant un [gel du déploiement](../../user/project/releases/_index.md#prevent-unintentional-releases-by-setting-a-deploy-freeze).

## Syntaxe Cron {#cron-syntax}

La planification Cron utilise une série de cinq nombres, séparés par des espaces :

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

(Source : [Wikipedia](https://en.wikipedia.org/wiki/Cron))

En syntaxe cron, l'astérisque (`*`) signifie « chaque », de sorte que les chaînes cron suivantes sont valides :

- Exécuter une fois par heure au début de l'heure : `0 * * * *`
- Exécuter une fois par jour à minuit : `0 0 * * *`
- Exécuter une fois par semaine à minuit le dimanche matin : `0 0 * * 0`
- Exécuter une fois par mois à minuit le premier jour du mois : `0 0 1 * *`
- Exécuter une fois par mois le 22 : `0 0 22 * *`
- Exécuter une fois par an à minuit le 1er janvier : `0 0 1 1 *`
- Exécuter deux fois par mois à 3 h, le 1er et le 15 du mois : `0 3 1,15 * *`

Pour une documentation complète sur cron, consultez la [page de manuel Linux crontab(5)](https://man7.org/linux/man-pages/man5/crontab.5.html). Cette documentation est accessible hors ligne en saisissant `man 5 crontab` dans un terminal Linux ou macOS.

De plus, GitLab utilise [`fugit`](#how-gitlab-parses-cron-syntax-strings), qui accepte la syntaxe `#` et `%`. Cette syntaxe peut ne pas fonctionner dans tous les testeurs cron :

- Exécuter une fois par mois le 2e lundi : `0 0 * * 1#2`. Cette syntaxe provient de l'[extension hash de `fugit`](https://github.com/floraison/fugit#the-hash-extension).
- Exécuter un dimanche sur deux à 9 h 00 : `0 9 * * sun%2`. Cette syntaxe provient de l'[extension modulo de `fugit`](https://github.com/floraison/fugit#the-modulo-extension).

## Exemples Cron {#cron-examples}

```plaintext
# Run at 7:00pm every day:
0 19 * * *

# Run every minute on the 3rd of June:
* * 3 6 *

# Run at 06:30 every Friday:
30 6 * * 5
```

D'autres exemples d'écriture d'une planification cron sont disponibles sur [crontab.guru](https://crontab.guru/examples.html).

## Comment GitLab analyse les chaînes de syntaxe cron {#how-gitlab-parses-cron-syntax-strings}

GitLab utilise [`fugit`](https://github.com/floraison/fugit) pour analyser les chaînes de syntaxe cron sur le serveur et [cron-validator](https://github.com/GuillaumeRochat/cron-validator) pour valider la syntaxe cron dans le navigateur. GitLab utilise [`cRonstrue`](https://github.com/bradymholt/cRonstrue) pour convertir les expressions cron en chaînes lisibles par l'utilisateur dans le navigateur.
