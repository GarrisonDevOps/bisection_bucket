---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Atlassian Bamboo
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez déclencher automatiquement des builds dans Atlassian Bamboo lorsque vous effectuez un push de modifications vers votre projet dans GitLab.

Bamboo ne fournit pas les mêmes fonctionnalités qu'un système de build traditionnel lors de l'acceptation de webhooks et de données de commit. Vous devez configurer un plan de build Bamboo avant de configurer l'intégration dans GitLab.

## Configurer Bamboo {#configure-bamboo}

1. Dans Bamboo, accédez à un plan de build et choisissez **Actions** > **Configurer le plan**.
1. Sélectionnez l'onglet **Déclencheurs**.
1. Sélectionnez **Ajouter un déclencheur**.
1. Saisissez une description comme `GitLab trigger`.
1. Sélectionnez **Le dépôt déclenche le build lorsque des modifications sont committées**.
1. Cochez la case correspondant à un ou plusieurs dépôts.
1. Saisissez l'adresse IP de GitLab dans **Adresses IP de déclenchement**. Ces adresses IP sont autorisées à déclencher des builds Bamboo.
1. Enregistrez le déclencheur.
1. Dans le volet de gauche, sélectionnez une étape de build. Si vous avez plusieurs étapes de build, sélectionnez la dernière étape contenant la tâche de checkout Git.
1. Sélectionnez l'onglet **Divers**.
1. Sous **Étiquetage par correspondance de modèle**, saisissez `${bamboo.repository.revision.number}` dans **Labels**.
1. Sélectionnez **Enregistrer**.

Bamboo est prêt à accepter des déclencheurs depuis GitLab. Ensuite, configurez l'intégration Bamboo dans GitLab.

## Configurer GitLab {#configure-gitlab}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Atlassian Bamboo**.
1. Assurez-vous que la case **Actif** est cochée.
1. Saisissez l'URL de base de votre serveur Bamboo. Par exemple, `https://bamboo.example.com`.
1. Facultatif. Décochez la case **Activer la vérification SSL** pour désactiver la [vérification SSL](_index.md#ssl-verification).
1. Saisissez la [clé de build](#identify-the-bamboo-build-plan-build-key) de votre plan de build Bamboo.
1. Si nécessaire, saisissez un nom d'utilisateur et un mot de passe pour un utilisateur Bamboo ayant accès au déclenchement du plan de build. Laissez ces champs vides si vous ne nécessitez pas d'authentification.
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

### Identifier la clé de build du plan de build Bamboo {#identify-the-bamboo-build-plan-build-key}

Une clé de build est un identifiant unique généralement composé de la clé de projet et de la clé de plan. Les clés de build sont courtes, entièrement en majuscules et séparées par un tiret (`-`), par exemple `PROJ-PLAN`.

La clé de build est incluse dans l'URL du navigateur lorsque vous consultez un plan dans Bamboo. Par exemple, `https://bamboo.example.com/browse/PROJ-PLAN`.

## Mettre à jour le statut de build Bamboo dans GitLab {#update-bamboo-build-status-in-gitlab}

Vous pouvez utiliser un script qui exploite l'[API de statut de commit](../../../api/commits.md#set-commit-pipeline-status) et les variables de build Bamboo pour :

- Mettre à jour le commit avec le statut de build.
- Ajouter l'URL du plan de build Bamboo comme `target_url` du commit.

Par exemple :

1. Créez un [jeton d'accès personnel](../../profile/personal_access_tokens.md) avec la portée définie sur `api`.
1. Enregistrez le jeton en tant que variable `$GITLAB_TOKEN` dans Bamboo.
1. Ajoutez le script suivant comme tâche finale aux jobs du plan Bamboo :

   ```shell
   #!/bin/bash

   # Script to update CI status on GitLab.
   # Add this script as final inline script task in a Bamboo job.
   #
   # General documentation: https://docs.gitlab.com/user/project/integrations/bamboo/
   # Fix inspired from https://gitlab.com/gitlab-org/gitlab/-/issues/34744

   # Stop at first error
   set -e

   # Access token. Set this as a CI variable in Bamboo.
   #GITLAB_TOKEN=

   # Status
   cistatus="failed"
   if [ "${bamboo_buildFailed}" = "false" ]; then
     cistatus="success"
   fi

   repo_url="${bamboo_planRepository_repositoryUrl}"

   # Check if SSH or HTTPS is in use
   protocol=${repo_url::4}
   if [ "$protocol" == "git@" ]; then
     repo=${repo_url:${#protocol}};
     gitlab_url=${repo%%:*};
   else
     protocol="https://"
     repo=${repo_url:${#protocol}};
     gitlab_url=${repo%%/*};
   fi

   start=$((${#gitlab_url} + 1)) # +1 for the / (https) or : (ssh)
   end=$((${#repo} - $start -4)) # -4 for the .git
   repo=${repo:$start:$end}
   repo=$(echo "$repo" | sed "s/\//%2F/g")

   # Send request
   url="https://${gitlab_url}/api/v4/projects/${repo}/statuses/${bamboo_planRepository_revision}?state=${cistatus}&target_url=${bamboo_buildResultsUrl}"
   echo "Sending request to $url"
   curl --fail --request POST --header "PRIVATE-TOKEN: $GITLAB_TOKEN" "$url"
   ```

## Dépannage {#troubleshooting}

### Builds non déclenchés {#builds-not-triggered}

Si les builds ne sont pas déclenchés, assurez-vous d'avoir saisi la bonne adresse IP de GitLab dans Bamboo sous **Adresses IP de déclenchement**. Vérifiez également les journaux du webhook d'intégration pour identifier les échecs de requête.

### Fonctionnalités avancées d'Atlassian Bamboo non disponibles dans l'interface GitLab {#advanced-atlassian-bamboo-features-not-available-in-gitlab-ui}

Les fonctionnalités avancées d'Atlassian Bamboo ne sont pas compatibles avec GitLab. Ces fonctionnalités comprennent, sans s'y limiter, la possibilité de consulter les journaux de build depuis l'interface GitLab.
