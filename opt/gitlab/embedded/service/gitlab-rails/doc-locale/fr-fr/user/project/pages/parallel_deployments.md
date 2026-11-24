---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Déploiements parallèles de GitLab Pages
description: "Publiez plusieurs versions d'un site GitLab Pages en même temps, chacune avec sa propre URL."
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/129534) dans GitLab 16.7 en tant que [version expérimentale](../../../policy/development_stages_support.md) [avec un feature flag](../../../administration/feature_flags/list.md) nommé `pages_multiple_versions_setting`. Fonctionnalité désactivée par défaut.
- [Renommé](https://gitlab.com/gitlab-org/gitlab/-/issues/480195) de « multiple deployments » en « parallel deployments » dans GitLab 17.4.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/422145) dans GitLab 17.4.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/502219) pour supprimer le paramètre de projet dans GitLab 17.7.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/507423) pour autoriser les points dans `path_prefix` dans GitLab 17.8.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/500000) pour autoriser les variables lorsqu'elles sont transmises à la propriété `publish` dans GitLab 17.9.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/487161) dans GitLab 17.9. Le feature flag `pages_multiple_versions_setting` a été supprimé.
- L'ajout automatique du chemin `pages.publish` à `artifacts:paths` a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/428018) dans GitLab 17.10 pour les jobs Pages uniquement.

{{< /history >}}

Avec les déploiements parallèles, vous pouvez publier plusieurs versions de votre site [GitLab Pages](_index.md) en même temps. Chaque version possède sa propre URL unique basée sur un préfixe de chemin que vous spécifiez.

Utilisez les déploiements parallèles pour :

- Améliorer votre workflow de test des modifications dans les branches de développement avant la fusion en production.
- Partager des aperçus fonctionnels avec les parties prenantes pour recueillir des commentaires.
- Maintenir la documentation de plusieurs versions de logiciels simultanément.
- Publier du contenu localisé pour différents publics.
- Créer des environnements de staging pour révision avant la publication finale.

Chaque version de votre site obtient sa propre URL basée sur un préfixe de chemin que vous spécifiez. Contrôlez la durée d'existence de ces déploiements parallèles. Ils expirent après 24 heures par défaut, mais vous pouvez personnaliser cette durée pour l'adapter à votre calendrier de révision.

## Créer un déploiement parallèle {#create-a-parallel-deployment}

Prérequis :

- L'espace de nommage racine doit disposer de [slots de déploiement parallèle](../../gitlab_com/_index.md#other-limits) disponibles.

Pour créer un déploiement parallèle :

1. Dans votre fichier `.gitlab-ci.yml`, ajoutez un job Pages avec un `path_prefix` :

   ```yaml
   pages:
     stage: deploy
     script:
       - echo "Pages accessible through ${CI_PAGES_URL}"
     pages:  # specifies that this is a Pages job and publishes the default public directory
       path_prefix: "$CI_COMMIT_BRANCH"
   ```

   La valeur `path_prefix` :

   - Est convertie en minuscules.
   - Peut contenir des chiffres (`0-9`), des lettres (`a-z`) et des points (`.`).
   - Est remplacée par des tirets (`-`) pour tout autre caractère.
   - Ne peut pas commencer ou se terminer par des tirets (`-`) ou des points (`.`), ils sont donc supprimés.
   - Doit faire 63 octets ou moins. Tout ce qui dépasse cette limite est tronqué.

1. Facultatif. Si vous souhaitez des préfixes dynamiques, utilisez des [variables CI/CD](../../../ci/variables/where_variables_can_be_used.md#gitlab-ciyml-file) dans votre `path_prefix`. Par exemple :

   ```yaml
   pages:
     path_prefix: "mr-$CI_MERGE_REQUEST_IID" # Results in paths like mr-123
   ```

1. Facultatif. Pour définir un délai d'expiration pour le déploiement, ajoutez `expire_in` :

   ```yaml
   pages:
     pages:
       path_prefix: "$CI_COMMIT_BRANCH"
       expire_in: 1 week
   ```

   Par défaut, les déploiements parallèles [expirent](#expiration) après 24 heures.

1. Commitez vos modifications et poussez-les vers votre dépôt.

Le déploiement est accessible à l'adresse :

- Avec un [domaine unique](_index.md#unique-domains) : `https://project-123456.gitlab.io/your-prefix-name`.
- Sans domaine unique : `https://namespace.gitlab.io/project/your-prefix-name`.

Le chemin d'URL entre le domaine du site et le répertoire public est déterminé par le `path_prefix`. Par exemple, si votre déploiement principal contient du contenu à l'adresse `/index.html`, un déploiement parallèle avec le préfixe `staging` peut accéder à ce même contenu à l'adresse `/staging/index.html`.

Pour éviter les conflits de chemins, évitez d'utiliser des préfixes de chemin correspondant aux noms de dossiers existants de votre site. Pour plus d'informations, consultez [conflit de chemins](#path-clash).

## Exemple de configuration {#example-configuration}

Prenons un projet tel que `https://gitlab.example.com/namespace/project`. Par défaut, son déploiement Pages principal est accessible via :

- Avec un [domaine unique](_index.md#unique-domains) : `https://project-123456.gitlab.io/`.
- Sans domaine unique : `https://namespace.gitlab.io/project`.

Si un `pages.path_prefix` est configuré avec les noms de branches du projet, comme `path_prefix = $CI_COMMIT_BRANCH`, et qu'il existe une branche nommée `username/testing_feature`, ce déploiement Pages parallèle serait accessible via :

- Avec un [domaine unique](_index.md#unique-domains) : `https://project-123456.gitlab.io/username-testing-feature`.
- Sans domaine unique : `https://namespace.gitlab.io/project/username-testing-feature`.

## Limites {#limits}

Le nombre de déploiements parallèles est limité par l'espace de nommage racine. Pour les limites spécifiques à :

- GitLab.com, consultez [autres limites](../../gitlab_com/_index.md#other-limits).
- GitLab Self-Managed, consultez [nombre de déploiements Pages parallèles](../../../administration/instance_limits.md#number-of-parallel-pages-deployments).

Pour réduire immédiatement le nombre de déploiements actifs dans votre espace de nommage, supprimez certains déploiements. Pour plus d'informations, consultez [supprimer un déploiement](_index.md#delete-a-deployment).

Pour configurer un délai d'expiration afin de supprimer automatiquement les anciens déploiements, consultez [déploiements expirés](_index.md#expiring-deployments).

## Expiration {#expiration}

Par défaut, les déploiements parallèles [expirent](_index.md#expiring-deployments) après 24 heures, après quoi ils sont supprimés. Si vous utilisez une instance auto-hébergée, l'administrateur de votre instance peut [configurer une durée par défaut différente](../../../administration/pages/_index.md#configure-the-default-expiry-for-parallel-deployments).

Pour personnaliser le délai d'expiration, [configurez `pages.expire_in`](_index.md#expiring-deployments).

Pour empêcher l'expiration automatique des déploiements, définissez `pages.expire_in` sur `never`.

## Conflit de chemins {#path-clash}

`pages.path_prefix` peut prendre des valeurs dynamiques à partir de [variables CI/CD](../../../ci/variables/_index.md) qui peuvent créer des déploiements Pages susceptibles d'entrer en conflit avec des chemins existants de votre site. Par exemple, pour un site GitLab Pages existant avec les chemins suivants :

```plaintext
/index.html
/documents/index.html
```

Si un `pages.path_prefix` est `documents`, cette version remplace le chemin existant. Autrement dit, `https://namespace.gitlab.io/project/documents/index.html` pointe vers `/index.html` sur le déploiement `documents` du site, au lieu de `documents/index.html` du déploiement `main` du site.

Combiner des [variables CI/CD](../../../ci/variables/_index.md) avec d'autres chaînes peut réduire le risque de conflit de chemins. Par exemple :

```yaml
create-pages:
  stage: deploy
  script:
    - echo "Pages accessible through ${CI_PAGES_URL}"
  variables:
    PAGES_PREFIX: "" # No prefix by default (main)
  pages:  # specifies that this is a Pages job and publishes the default public directory
    path_prefix: "$PAGES_PREFIX"
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH # Run on default branch (with default PAGES_PREFIX)
    - if: $CI_COMMIT_BRANCH == "staging" # Run on main (with default PAGES_PREFIX)
      variables:
        PAGES_PREFIX: '_stg' # Prefix with _stg for the staging branch
    - if: $CI_PIPELINE_SOURCE == "merge_request_event" # Conditionally change the prefix for Merge Requests
      when: manual # Run pages manually on Merge Requests
      variables:
        PAGES_PREFIX: 'mr-$CI_MERGE_REQUEST_IID' # Prefix with the mr-<iid>, like `mr-123`
```

Voici d'autres exemples de combinaison de [variables](../../../ci/variables/_index.md) avec des chaînes pour des préfixes dynamiques :

- `pages.path_prefix: 'mr-$CI_COMMIT_REF_SLUG'` : nom de branche ou de tag préfixé par `mr-`, comme `mr-branch-name`.
- `pages.path_prefix: '_${CI_MERGE_REQUEST_IID}_'` : numéro de merge request préfixé et suffixé par `_`, comme `_123_`.

L'exemple YAML précédent utilise des [noms de job définis par l'utilisateur](_index.md#user-defined-job-names).

## Utiliser les déploiements parallèles pour créer des environnements Pages {#use-parallel-deployments-to-create-pages-environments}

Vous pouvez utiliser des déploiements GitLab Pages parallèles pour créer un nouvel [environnement](../../../ci/environments/_index.md). Par exemple :

```yaml
create-pages:
  stage: deploy
  script:
    - echo "Pages accessible through ${CI_PAGES_URL}"
  variables:
    PAGES_PREFIX: "" # no prefix by default (run on the default branch)
  pages:  # specifies that this is a Pages job and publishes the default public directory
    path_prefix: "$PAGES_PREFIX"
  environment:
    name: "Pages ${PAGES_PREFIX}"
    url: $CI_PAGES_URL
  rules:
    - if: $CI_COMMIT_BRANCH == "staging" # ensure to run on the default branch (with default PAGES_PREFIX)
      variables:
        PAGES_PREFIX: '_stg' # prefix with _stg for the staging branch
    - if: $CI_PIPELINE_SOURCE == "merge_request_event" # conditionally change the prefix on Merge Requests
      when: manual # run pages manually on Merge Requests
      variables:
        PAGES_PREFIX: 'mr-$CI_MERGE_REQUEST_IID' # prefix with the mr-<iid>, like `mr-123`
```

Avec cette configuration, les utilisateurs ont accès à chaque déploiement GitLab Pages via l'interface utilisateur. Lorsque vous utilisez des [environnements](../../../ci/environments/_index.md) pour Pages, tous les environnements Pages sont répertoriés dans la liste des environnements du projet.

Vous pouvez également [regrouper des environnements similaires](../../../ci/environments/_index.md#group-similar-environments).

L'exemple YAML précédent utilise des [noms de job définis par l'utilisateur](_index.md#user-defined-job-names).

### Nettoyage automatique {#auto-clean}

Les déploiements Pages parallèles, créés par une merge request avec un `path_prefix`, sont automatiquement supprimés lorsque la merge request est fermée ou fusionnée.

## Utilisation avec les redirections {#usage-with-redirects}

Les redirections utilisent des chemins absolus. Étant donné que les déploiements parallèles sont disponibles sur un sous-chemin, les redirections nécessitent des modifications supplémentaires du fichier `_redirects` pour fonctionner dans les déploiements parallèles.

Les fichiers existants ont toujours la priorité sur une règle de redirection, vous pouvez donc utiliser un caractère générique splat pour intercepter les requêtes vers des chemins préfixés.

Si votre `path_prefix` est `/mr-${$CI_MERGE_REQUEST_IID}`, adaptez cet exemple de fichier `_redirect` pour rediriger les requêtes vers les déploiements principal et parallèles :

```shell
# Redirect the primary deployment
/will-redirect.html /redirected.html 302

# Redirect parallel deployments
/*/will-redirect.html /:splat/redirected.html 302
```
