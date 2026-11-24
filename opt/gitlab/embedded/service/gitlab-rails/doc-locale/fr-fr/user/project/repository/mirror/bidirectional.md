---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Créez des miroirs bidirectionnels pour envoyer et récupérer des modifications entre deux dépôts Git.
title: Mise en miroir bidirectionnelle
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Déplacé vers GitLab Premium dans la version 13.9.

{{< /history >}}

> [!warning]
> La mise en miroir bidirectionnelle peut provoquer des conflits.

La [mise en miroir](_index.md) bidirectionnelle configure deux dépôts pour qu'ils effectuent chacun des opérations pull et push l'un vers l'autre. Rien ne garantit que l'un ou l'autre des dépôts puisse se mettre à jour sans erreurs.

## Réduire les conflits dans la mise en miroir bidirectionnelle {#reduce-conflicts-in-bidirectional-mirroring}

Si vous configurez la mise en miroir bidirectionnelle, préparez vos dépôts à la gestion des conflits. Configurez-les pour réduire les conflits et définissez comment les résoudre lorsqu'ils surviennent :

- [Mettre en miroir uniquement les branches protégées](_index.md#mirror-only-protected-branches). La réécriture d'un commit mis en miroir sur l'un ou l'autre des remotes provoque des conflits et un échec de la mise en miroir.
- [Protégez les branches](../branches/protected.md) que vous souhaitez mettre en miroir sur les deux remotes afin d'éviter les conflits causés par la réécriture de l'historique.
- Réduisez le délai de mise en miroir grâce à un [webhook d'événement push](../../integrations/webhook_events.md#push-events). La mise en miroir bidirectionnelle crée une situation de compétition (race condition) où des commits effectués de manière rapprochée sur la même branche provoquent des conflits. Les webhooks d'événements push peuvent aider à atténuer la situation de compétition. La mise en miroir push depuis GitLab est soumise à une limite de débit d'une fois par minute lorsque seules les branches protégées sont mises en miroir par push.
- Prévenir les conflits [en utilisant un hook pre-receive](#prevent-conflicts-by-using-a-pre-receive-hook).

## Configurer un webhook pour déclencher un pull immédiat vers GitLab {#configure-a-webhook-to-trigger-an-immediate-pull-to-gitlab}

Un [webhook d'événement push](../../integrations/webhook_events.md#push-events) dans l'instance aval peut aider à réduire les situations de compétition en synchronisant les modifications plus fréquemment.

Prérequis :

- Vous avez configuré les miroirs [push](push.md#set-up-a-push-mirror-to-another-gitlab-instance-with-2fa-activated) et [pull](pull.md) dans l'instance GitLab amont.

Pour créer le webhook dans l'instance aval :

1. Créez un [jeton d'accès personnel](../../../profile/personal_access_tokens.md) avec la portée `API`.
1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Webhooks**.
1. Ajoutez l'**URL** du webhook qui (dans ce cas) utilise la requête de l'[API de miroir pull](../../../../api/project_pull_mirroring.md#start-the-pull-mirroring-process-for-a-project) pour déclencher un pull immédiat après la mise à jour d'un dépôt :

   ```plaintext
   https://gitlab.example.com/api/v4/projects/:id/mirror/pull?private_token=<your_access_token>
   ```

1. [Masquez votre jeton](../../integrations/webhooks.md#mask-sensitive-portions-of-webhook-urls).
1. Sélectionnez **Push Events**.
1. Sélectionnez **Add Webhook**.

Pour tester l'intégration, sélectionnez **Test** et vérifiez que GitLab ne renvoie pas de message d'erreur.

## Prévenir les conflits en utilisant un hook pre-receive {#prevent-conflicts-by-using-a-pre-receive-hook}

> [!warning]
> Cette solution a un impact négatif sur les performances des opérations de push Git, car elles sont proxysées vers le dépôt Git amont.

Dans cette configuration, un dépôt Git joue le rôle de source faisant autorité (upstream) et l'autre celui de destination (downstream). Ce hook côté serveur `pre-receive` n'accepte un push qu'après avoir d'abord envoyé le commit vers le dépôt amont. Installez ce hook sur votre dépôt aval.

Par exemple :

```shell
#!/usr/bin/env bash

# --- Assume only one push mirror target
# Push mirroring remotes are named `remote_mirror_<id>`.
# This line finds the first remote and uses that.
TARGET_REPO=$(git remote | grep -m 1 remote_mirror)

proxy_push()
{
  # --- Arguments
  OLDREV=$(git rev-parse $1)
  NEWREV=$(git rev-parse $2)
  REFNAME="$3"

  # --- Pattern of branches to proxy pushes
  allowlist=$(expr "$branch" : "\(master\)")

  case "$refname" in
    refs/heads/*)
      branch=$(expr "$refname" : "refs/heads/\(.*\)")

      if [ "$allowlist" = "$branch" ]; then
        # handle https://git-scm.com/docs/git-receive-pack#_quarantine_environment
        unset GIT_QUARANTINE_PATH
        error="$(git push --quiet $TARGET_REPO $NEWREV:$REFNAME 2>&1)"
        fail=$?

        if [ "$fail" != "0" ]; then
          echo >&2 ""
          echo >&2 " Error: updates were rejected by upstream server"
          echo >&2 "   This is usually caused by another repository pushing changes"
          echo >&2 "   to the same ref. You may want to first integrate remote changes"
          echo >&2 ""
          return
        fi
      fi
      ;;
  esac
}

# Allow dual mode: run from the command line just like the update hook, or
# if no arguments are given, then run as a hook script:
if [ -n "$1" -a -n "$2" -a -n "$3" ]; then
  # Output to the terminal in command line mode. If someone wanted to
  # resend an email, they could redirect the output to sendmail themselves
  PAGER= proxy_push $2 $3 $1
else
  # Push is proxied upstream one ref at a time. It is possible for some refs
  # to succeed, and others to fail. This results in a failed push.
  while read oldrev newrev refname
  do
    proxy_push $oldrev $newrev $refname
  done
fi
```

Cet exemple présente quelques limitations :

- Il peut ne pas fonctionner pour votre cas d'usage sans modification :
  - Il ne prend pas en compte les différents types de mécanismes d'authentification pour le miroir.
  - Il ne fonctionne pas avec les mises à jour forcées (réécriture de l'historique).
  - Seules les branches correspondant aux patterns `allowlist` font l'objet d'un push proxy.
- Le script contourne l'environnement de quarantaine du hook Git car la mise à jour de `$TARGET_REPO` est considérée comme une mise à jour de référence (ref update), ce qui génère des avertissements Git.

## Sujets connexes {#related-topics}

- [Dépannage](troubleshooting.md) de la mise en miroir de dépôt.
- [Configurer les hooks serveur](../../../../administration/server_hooks.md)
