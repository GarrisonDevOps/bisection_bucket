---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Créez un miroir en tirage pour récupérer les modifications d'un dépôt distant dans GitLab et maintenir votre copie à jour."
title: Tirer depuis un dépôt distant
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Déplacé vers GitLab Premium dans la version 13.9.

{{< /history >}}

Vous pouvez utiliser l'interface GitLab pour parcourir le contenu et l'activité d'un dépôt, même s'il n'est pas hébergé sur GitLab. Créez un [miroir](_index.md) en tirage pour copier les branches, les tags et les commits d'un dépôt amont vers le vôtre.

Contrairement aux [miroirs en poussée](push.md), les miroirs en tirage récupèrent les modifications d'un dépôt amont (distant) selon une planification. Pour éviter que le miroir ne diverge du dépôt amont, n'envoyez pas de commits directement vers le miroir aval. Envoyez plutôt les commits vers le dépôt amont. Les modifications du dépôt distant sont tirées dans le dépôt GitLab :

- Automatiquement, 30 minutes après un tirage précédent. Cette option ne peut pas être désactivée.
- Lorsqu'un administrateur [force la mise à jour du miroir](_index.md#force-an-update).
- Lorsqu'un [appel API déclenche une mise à jour](#trigger-an-update-by-using-the-api).

Les mises à jour via l'interface utilisateur et l'API sont soumises aux [intervalles de miroir en tirage](../../../../administration/instance_limits.md#pull-mirroring-interval) par défaut de 5 minutes. Cet intervalle peut être configuré sur les instances GitLab Self-Managed.

Par défaut, si une branche ou un tag du miroir en tirage aval diverge du dépôt local, GitLab cesse de mettre à jour la branche. Cela permet d'éviter toute perte de données. Les branches et les tags supprimés dans le dépôt amont ne sont pas répercutés dans le dépôt aval.

> [!note]
> Les éléments supprimés du dépôt miroir en tirage aval, mais toujours présents dans le dépôt amont, sont restaurés lors du prochain tirage. Par exemple : une branche supprimée uniquement dans le dépôt miroir réapparaît après le prochain tirage.

## Fonctionnement du miroir en tirage {#how-pull-mirroring-works}

Après avoir configuré un dépôt GitLab en tant que miroir en tirage :

1. GitLab ajoute le dépôt à une file d'attente.
1. Une fois par minute, un job cron Sidekiq planifie la mise à jour des miroirs de dépôts, en fonction des éléments suivants :
   - La capacité disponible, déterminée par les paramètres Sidekiq. Pour GitLab.com, consultez les [paramètres Sidekiq de GitLab.com](../../../gitlab_com/_index.md#sidekiq).
   - Le nombre de miroirs déjà dans la file d'attente et en attente de mise à jour. L'échéance dépend de la date de la dernière mise à jour du miroir de dépôt et du nombre de nouvelles tentatives de mise à jour effectuées.
1. Sidekiq devient disponible pour traiter les mises à jour, et les miroirs sont mis à jour. Si le processus de mise à jour :
   - Réussit : une mise à jour est à nouveau mise en file d'attente avec un délai d'attente d'au moins 30 minutes.
   - Échoue : la mise à jour est tentée à nouveau ultérieurement. Après 14 échecs, un miroir est marqué comme [échec irrécupérable](#fix-hard-failures-when-mirroring) et n'est plus mis en file d'attente pour les mises à jour. La divergence d'une branche par rapport à son équivalent amont peut entraîner des échecs. Pour éviter la divergence des branches, configurez l'option [écraser les branches divergentes](#overwrite-diverged-branches) lors de la création de votre miroir.

## Configurer le miroir en tirage {#configure-pull-mirroring}

Prérequis :

- Si votre dépôt distant est sur GitHub et que vous avez configuré l'[authentification à deux facteurs (2FA)](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa), créez un [jeton d'accès personnel pour GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) avec la portée `repo`. Si la 2FA est activée, ce jeton d'accès personnel sert de mot de passe GitHub.
- Le [mode silencieux GitLab](../../../../administration/silent_mode/_index.md) n'est pas activé.
- Le dépôt amont et votre dépôt GitLab utilisent le même format d'objet. Vous ne pouvez pas effectuer de miroir entre des dépôts SHA-1 et SHA-256.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Dépôts miroirs**.
1. Saisissez l'**URL du dépôt Git**.

   > [!note]
   > Pour effectuer le miroir du dépôt `gitlab`, utilisez `gitlab.com:gitlab-org/gitlab.git` ou `https://gitlab.com/gitlab-org/gitlab.git`.

1. Dans **Sens du miroir**, sélectionnez **Tirage**.
1. Dans **Méthode d'authentification**, sélectionnez votre méthode d'authentification. Pour plus d'informations, consultez [les méthodes d'authentification pour les miroirs](_index.md#authentication-methods-for-mirrors).
1. Sélectionnez les options dont vous avez besoin :
   - [**Écraser les branches divergentes**](#overwrite-diverged-branches)
   - [**Déclencher des pipelines pour les mises à jour de miroirs**](#trigger-pipelines-for-mirror-updates)
   - **Mettre en miroir uniquement les branches protégées**
1. Pour enregistrer la configuration, sélectionnez **Dépôt miroir**.

### Écraser les branches divergentes {#overwrite-diverged-branches}

{{< history >}}

- Déplacé vers GitLab Premium dans la version 13.9.

{{< /history >}}

Pour toujours mettre à jour vos branches locales avec les versions distantes, même si elles ont divergé du dépôt distant, sélectionnez **Écraser les branches divergentes** lors de la création d'un miroir.

> [!warning]
> Pour les branches en miroir, l'activation de cette option entraîne la perte des modifications locales.

### Déclencher des pipelines pour les mises à jour de miroirs {#trigger-pipelines-for-mirror-updates}

{{< history >}}

- Déplacé vers GitLab Premium dans la version 13.9.

{{< /history >}}

Vous pouvez configurer votre miroir pour déclencher automatiquement des pipelines lorsque le dépôt distant met à jour des branches ou des tags. Avant d'activer cette fonctionnalité :

- Assurez-vous que vos runners CI peuvent gérer la charge supplémentaire liée à l'activité du dépôt distant.
- Tenez compte des risques de sécurité, car les pipelines utilisent les identifiants de l'utilisateur qui a configuré le miroir en tirage. Par exemple, un mainteneur malveillant pourrait :
  - Effectuer une mise à jour du dépôt distant qui tente de récupérer les valeurs de variables CI/CD stockées lors de l'exécution du pipeline.
  - Envoyer des commits vers votre projet en miroir si le paramètre [**Autoriser les requêtes de poussée Git dans le dépôt**](../../../../ci/jobs/ci_job_token.md#allow-git-push-requests-to-your-project-repository) est activé.

> [!warning]
> N'activez cette fonctionnalité que pour vos propres projets ou ceux dont les mainteneurs sont de confiance.

## Miroir en tirage avec application de l'authentification unique (SSO) {#pull-mirroring-with-sso-enforcement}

Lorsque l'[application de l'authentification unique (SSO)](../../../group/saml_sso/_index.md#sso-enforcement) est activée pour votre groupe, l'utilisateur qui a créé le miroir doit maintenir une session SSO active, faute de quoi le miroir échoue.

Pour configurer le miroir sans dépendance à la session SSO, vous pouvez utiliser l'[API de miroir en tirage](../../../../api/project_pull_mirroring.md) avec un [jeton d'accès au projet](../../settings/project_access_tokens.md), un [jeton d'accès au groupe](../../../group/settings/group_access_tokens.md) ou un [jeton d'accès personnel](../../../profile/personal_access_tokens.md) pour les comptes de service.

## Déclencher une mise à jour via l'API {#trigger-an-update-by-using-the-api}

{{< history >}}

- Déplacé vers GitLab Premium dans la version 13.9.

{{< /history >}}

Le miroir en tirage utilise l'interrogation pour détecter les nouvelles branches et les commits ajoutés en amont, souvent quelques minutes après. Vous pouvez notifier GitLab via un [appel API](../../../../api/project_pull_mirroring.md#start-the-pull-mirroring-process-for-a-project), mais l'[intervalle minimal pour les limites du miroir en tirage](_index.md#force-an-update) reste appliqué.

Pour plus d'informations, consultez [démarrer le processus de miroir en tirage pour un projet](../../../../api/project_pull_mirroring.md#start-the-pull-mirroring-process-for-a-project).

## Résoudre les échecs irrécupérables lors de la mise en miroir {#fix-hard-failures-when-mirroring}

{{< history >}}

- Déplacé vers GitLab Premium dans la version 13.9.

{{< /history >}}

Après 14 tentatives infructueuses consécutives, le processus de mise en miroir est marqué comme un échec irrécupérable et les tentatives de mise en miroir s'arrêtent. Cet échec est visible dans l'un ou l'autre des éléments suivants :

- Tableau de bord principal du projet.
- Page des paramètres du miroir en tirage.

Pour reprendre la mise en miroir du projet, [forcez une mise à jour](_index.md#force-an-update).

Si plusieurs projets sont affectés par ce problème, par exemple après une longue panne réseau ou serveur, vous pouvez utiliser la [console Rails](../../../../administration/operations/rails_console.md) pour identifier et mettre à jour tous les projets affectés avec cette commande :

```ruby
Project.find_each do |p|
  if p.import_state && p.import_state.retry_count >= 14
    puts "Resetting mirroring operation for #{p.full_path}"
    p.import_state.reset_retry_count
    p.import_state.set_next_execution_to_now(prioritized: true)
    p.import_state.save!
  end
end
```

## Sujets connexes {#related-topics}

- [Dépannage](troubleshooting.md) pour la mise en miroir de dépôts.
- [Intervalles de miroir en tirage](../../../../administration/instance_limits.md#pull-mirroring-interval)
- [API de miroir en tirage de projet](../../../../api/project_pull_mirroring.md#update-project-pull-mirroring-settings)
