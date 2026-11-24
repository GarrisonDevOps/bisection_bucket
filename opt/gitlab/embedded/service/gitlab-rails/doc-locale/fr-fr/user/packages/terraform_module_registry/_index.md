---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Registre des modules Terraform
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Avec le Registre des modules Terraform, vous pouvez :

- Utiliser des projets GitLab comme registre privé pour les modules Terraform.
- Créer et publier des modules avec GitLab CI/CD, qui peuvent ensuite être utilisés depuis d'autres projets privés.

## S'authentifier auprès du Registre des modules Terraform {#authenticate-to-the-terraform-module-registry}

Pour vous authentifier auprès du Registre des modules Terraform, vous avez besoin de l'un des éléments suivants :

- Un [jeton d'accès personnel](../../profile/personal_access_tokens.md) avec au moins la portée `read_api`.
- Un [jeton de job CI/CD](../../../ci/jobs/ci_job_token.md).
- Un [jeton de déploiement](../../project/deploy_tokens/_index.md) avec la portée `read_package_registry` ou `write_package_registry`, ou les deux.

Lors de l'utilisation de l'API :

- Si vous vous authentifiez avec un jeton de déploiement, vous devez appliquer la portée `write_package_registry` pour publier un module. Pour télécharger un module, appliquez la portée `read_package_registry`.
- Si vous vous authentifiez avec un jeton d'accès personnel, vous devez le configurer avec au moins la portée `read_api`.

N'utilisez pas de méthodes d'authentification autres que celles documentées ici. Les méthodes d'authentification non documentées peuvent être supprimées à l'avenir.

## Prérequis {#prerequisites}

Pour publier un module Terraform :

- Vous devez disposer du rôle Développeur, Chargé de maintenance ou Propriétaire.

Pour supprimer un module :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire.

## Publier un module Terraform {#publish-a-terraform-module}

La publication d'un module Terraform le crée s'il n'existe pas.

Après avoir publié un module Terraform, vous pouvez [le consulter dans la page **Registre des modules Terraform**](#view-terraform-modules).

### Avec l'API {#with-the-api}

Publiez des modules Terraform en utilisant l'[API du Registre des modules Terraform](../../../api/packages/terraform-modules.md).

```plaintext
PUT /projects/:id/packages/terraform/modules/:module-name/:module-system/:module-version/file
```

| Attribut          | Type            | Obligatoire | Description                                                                                                                      |
| -------------------| --------------- | ---------| -------------------------------------------------------------------------------------------------------------------------------- |
| `id`               | entier/chaîne  | oui      | L'ID ou le [chemin encodé en URL du projet](../../../api/rest/_index.md#namespaced-paths).                                    |
| `module-name`      | Chaîne          | oui      | Le nom du module. Syntaxe prise en charge : 1 à 64 caractères ASCII, comprenant des lettres minuscules (a-z) et des chiffres (0-9). |
| `module-system`    | Chaîne          | oui      | Le système du module. Syntaxe prise en charge : 1 à 64 caractères ASCII, comprenant des lettres minuscules (a-z) et des chiffres (0-9). Pour plus d'informations, consultez le [protocole du registre de modules](https://opentofu.org/docs/internals/module-registry-protocol/). |
| `module-version`   | Chaîne          | oui      | La version du module. Doit suivre la [spécification de gestion sémantique de version](https://semver.org/). |

Fournissez le contenu du fichier dans le corps de la requête.

Les requêtes doivent se terminer par `/file`. Si vous envoyez une requête se terminant par autre chose, cela génère une erreur `404 Not Found`.

{{< tabs >}}

{{< tab title="Jeton d'accès personnel" >}}

Exemple de requête utilisant un jeton d'accès personnel :

```shell
curl --fail-with-body --header "PRIVATE-TOKEN: <your_access_token>" \
     --upload-file path/to/file.tgz \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/packages/terraform/modules/<your_module>/<your_system>/0.0.1/file"
```

{{< /tab >}}

{{< tab title="Jeton de déploiement" >}}

Exemple de requête utilisant un jeton de déploiement :

```shell
curl --fail-with-body --header "DEPLOY-TOKEN: <deploy_token>" \
     --upload-file path/to/file.tgz \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/packages/terraform/modules/<your_module>/<your_system>/0.0.1/file"
```

{{< /tab >}}

{{< /tabs >}}

Exemple de réponse :

```json
{
  "message":"201 Created"
}
```

### Avec un template CI/CD (recommandé) {#with-a-cicd-template-recommended}

Vous pouvez utiliser le template CI/CD [`Terraform-Module.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Terraform-Module.gitlab-ci.yml) ou le template avancé [`Terraform/Module-Base.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Terraform/Module-Base.gitlab-ci.yml) pour publier un module Terraform dans le Registre des modules Terraform GitLab :

```yaml
include:
  template: Terraform-Module.gitlab-ci.yml
```

Le pipeline contient les jobs suivants :

- `fmt` : valide le formatage du module Terraform
- `kics-iac-sast` : teste le module Terraform pour détecter des problèmes de sécurité
- `deploy` : déploie le module Terraform dans le Registre des modules Terraform (pour les pipelines de tags uniquement)

#### Utiliser des variables de pipeline {#use-pipeline-variables}

Configurez le pipeline avec les variables suivantes :

| Variable                   | Valeur par défaut              | Description                                                                                     |
|----------------------------|----------------------|-------------------------------------------------------------------------------------------------|
| `TERRAFORM_MODULE_DIR`     | `${CI_PROJECT_DIR}`  | Le chemin relatif vers le répertoire racine du projet Terraform.                               |
| `TERRAFORM_MODULE_NAME`    | `${CI_PROJECT_NAME}` | Le nom du module. Ne doit contenir ni espaces ni underscores.                  |
| `TERRAFORM_MODULE_SYSTEM`  | `local`              | Le système ou fournisseur ciblé par votre module. Par exemple, `local`, `aws` ou `google`. |
| `TERRAFORM_MODULE_VERSION` | `${CI_COMMIT_TAG}`   | La version du module. Doit suivre la [spécification de gestion sémantique de version](https://semver.org/).          |

### Configurer CI/CD manuellement {#configure-cicd-manually}

Pour utiliser des modules Terraform dans [GitLab CI/CD](../../../ci/_index.md), utilisez un `CI_JOB_TOKEN` à la place du jeton d'accès personnel dans vos commandes.

Par exemple, ce job charge un nouveau module pour le [fournisseur système](https://registry.terraform.io/browse/providers) `local` et utilise la version du module issue du tag de commit Git :

```yaml
stages:
  - deploy

upload:
  stage: deploy
  image: curlimages/curl:latest
  variables:
    TERRAFORM_MODULE_DIR: ${CI_PROJECT_DIR}    # The relative path to the root directory of the Terraform project.
    TERRAFORM_MODULE_NAME: ${CI_PROJECT_NAME}  # The name of your Terraform module, must not have any spaces or underscores (will be translated to hyphens).
    TERRAFORM_MODULE_SYSTEM: local             # The system or provider your Terraform module targets (ex. local, aws, google).
    TERRAFORM_MODULE_VERSION: ${CI_COMMIT_TAG} # The version - it's recommended to follow SemVer for Terraform Module Versioning.
  script:
    - TERRAFORM_MODULE_NAME=$(echo "${TERRAFORM_MODULE_NAME}" | tr " _" -) # module-name must not have spaces or underscores, so translate them to hyphens
    - tar -vczf /tmp/${TERRAFORM_MODULE_NAME}-${TERRAFORM_MODULE_SYSTEM}-${TERRAFORM_MODULE_VERSION}.tgz -C ${TERRAFORM_MODULE_DIR} --exclude=./.git .
    - 'curl --fail-with-body --location --header "JOB-TOKEN: ${CI_JOB_TOKEN}"
         --upload-file /tmp/${TERRAFORM_MODULE_NAME}-${TERRAFORM_MODULE_SYSTEM}-${TERRAFORM_MODULE_VERSION}.tgz
         ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/terraform/modules/${TERRAFORM_MODULE_NAME}/${TERRAFORM_MODULE_SYSTEM}/${TERRAFORM_MODULE_VERSION}/file'
  rules:
    - if: $CI_COMMIT_TAG
```

Pour déclencher ce job de chargement, ajoutez un tag Git à votre commit. Assurez-vous que le tag suit la [spécification de gestion sémantique de version](https://semver.org/) requise pour Terraform. La `rules:if: $CI_COMMIT_TAG` garantit que seuls les commits tagués dans votre dépôt déclenchent le job de chargement du module.

Pour d'autres façons de contrôler les jobs dans votre pipeline CI/CD, consultez la [référence de syntaxe YAML CI/CD](../../../ci/yaml/_index.md).

### Workflow de résolution de module {#module-resolution-workflow}

Lorsque vous chargez un nouveau module, GitLab génère un chemin pour le module. Par exemple :

- `https://gitlab.example.com/parent-group/my-infra-package`

Ce chemin est conforme au [protocole du Registre des modules Terraform](https://opentofu.org/docs/internals/module-registry-protocol/), où :

- `gitlab.example.com` est le nom d'hôte.
- `parent-group` est l'[espace de nommage](../../namespace/_index.md) unique de premier niveau du Registre des modules Terraform.
- `my-infra-package` est le nom du module.

Si les [doublons ne sont pas autorisés](#allow-duplicate-terraform-modules), le nom et la version du module doivent être uniques dans tous les groupes, sous-groupes et projets sous `parent-group`. Sinon, vous recevez l'erreur suivante :

- `{"message":"A module with the same name already exists in the namespace."}`

Si les [doublons sont autorisés](#allow-duplicate-terraform-modules), la résolution du module est basée sur le module le plus récemment publié.

Par exemple, si :

- Le projet est `gitlab.example.com/parent-group/subgroup/my-project`.
- Le module Terraform est `my-infra-package`.

Si les doublons sont autorisés, `my-infra-package` est un module valide. Si les doublons ne sont pas autorisés, le nom du module doit être unique dans tous les projets de tous les groupes sous `parent-group`.

Lorsque vous nommez un module, gardez ces conventions de nommage à l'esprit :

- Les noms de votre projet et de votre groupe ne doivent pas inclure de point (`.`). Par exemple, `source = "gitlab.example.com/my.group/project.name"` est invalide.
- Les versions de module doivent suivre la [spécification de gestion sémantique de version](https://semver.org/).

### Autoriser les modules Terraform dupliqués {#allow-duplicate-terraform-modules}

{{< history >}}

- Le rôle requis a été [modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/370471) de Maintainer à Owner dans GitLab 17.0.

{{< /history >}}

Par défaut, le Registre des modules Terraform impose l'unicité des noms de modules dans le même espace de nommage.

Pour autoriser la publication de noms de modules dupliqués :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Dans la ligne **Module Terraform** du tableau **Paquets dupliqués**, désactivez le bouton **Autoriser les doublons**.
1. Facultatif. Dans la zone de texte **Exception**, saisissez une expression régulière correspondant aux noms des modules à autoriser.

Vos modifications sont automatiquement enregistrées.

> [!note]
> Si **Autoriser les doublons** est activé, vous pouvez spécifier les noms de modules qui ne doivent pas avoir de doublons dans la zone de texte **Exception**.

Vous pouvez également autoriser la publication de noms dupliqués en activant `terraform_module_duplicates_allowed` dans l'[API GraphQL](../../../api/graphql/reference/_index.md#packagesettings).

Pour autoriser les doublons avec des noms spécifiques :

1. Assurez-vous que `terraform_module_duplicates_allowed` est désactivé.
1. Utilisez `terraform_module_duplicate_exception_regex` pour définir un modèle d'expression régulière pour les noms de modules pour lesquels vous souhaitez autoriser les doublons.

Le paramètre d'espace de nommage de premier niveau est prioritaire sur les paramètres des espaces de nommage enfants. Par exemple, si vous activez `terraform_module_duplicates_allowed` pour un groupe et le désactivez pour un sous-groupe, les doublons sont autorisés pour tous les projets du groupe et de ses sous-groupes.

Pour plus d'informations sur la résolution de module, consultez le [workflow de résolution de module](#module-resolution-workflow).

## Afficher les modules Terraform {#view-terraform-modules}

{{< history >}}

- La prise en charge des fichiers `README` a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/438060) dans GitLab 17.2.

{{< /history >}}

Pour afficher les modules Terraform dans votre projet ou groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Opération** > **Modules Terraform**.

Vous pouvez rechercher, trier et filtrer les modules sur cette page.

Pour afficher le fichier `README` d'un module :

1. Depuis la page **Registre des modules Terraform**, sélectionnez un module Terraform.
1. Sélectionnez **`README`**.

## Référencer un module Terraform {#reference-a-terraform-module}

Référencez un module depuis un groupe ou un projet.

### Depuis un espace de nommage {#from-a-namespace}

Vous pouvez fournir des jetons d'authentification (jetons de job, jetons d'accès personnels ou jetons de déploiement) pour `terraform` dans des variables d'environnement.

Vous devez ajouter le préfixe `TF_TOKEN_` au nom de domaine des variables d'environnement, en encodant les points sous forme d'underscores. Pour plus d'informations, consultez les [identifiants de variable d'environnement](https://opentofu.org/docs/cli/config/config-file/#environment-variable-credentials).

Par exemple, la valeur d'une variable nommée `TF_TOKEN_gitlab_com` est utilisée comme jeton de déploiement lorsque l'interface de ligne de commande effectue des requêtes de service vers le nom d'hôte `gitlab.com` :

```shell
export TF_TOKEN_gitlab_com='glpat-<deploy_token>'
```

Cette méthode est recommandée pour les implémentations en entreprise. Pour les environnements locaux ou temporaires, vous pouvez créer un fichier `~/.terraformrc` ou `%APPDATA%/terraform.rc` :

```terraform
credentials "<gitlab.com>" {
  token = "<TOKEN>"
}
```

Où `gitlab.com` peut être remplacé par le nom d'hôte de votre instance GitLab Self-Managed.

Vous pouvez ensuite faire référence à votre module Terraform depuis un projet Terraform en aval :

```terraform
module "<module>" {
  source = "gitlab.com/<namespace>/<module-name>/<module-system>"
}
```

### Depuis un projet {#from-a-project}

Pour référencer un module Terraform à l'aide d'une source de projet, utilisez le type de source [récupération d'archives via HTTP](https://developer.hashicorp.com/terraform/language/modules/sources#fetching-archives-over-http) fourni par Terraform.

Vous pouvez fournir des jetons d'authentification (jetons de job, jetons d'accès personnels ou jetons de déploiement) pour `terraform` dans votre fichier `~/.netrc` :

```plaintext
machine <gitlab.com>
login <USERNAME>
password <TOKEN>
```

Où `gitlab.com` peut être remplacé par le nom d'hôte de votre instance GitLab Self-Managed, et `<USERNAME>` est votre nom d'utilisateur de jeton.

Vous pouvez faire référence à votre module Terraform depuis un projet Terraform en aval :

```terraform
module "<module>" {
  source = "https://gitlab.com/api/v4/projects/<project-id>/packages/terraform/modules/<module-name>/<module-system>/<module-version>"
}
```

Si vous devez référencer la dernière version d'un module, vous pouvez omettre `<module-version>` dans l'URL source. Pour éviter tout problème futur, référencez une version spécifique si possible.

S'il existe des [noms de modules dupliqués](#allow-duplicate-terraform-modules) dans le même espace de nommage, le référencement du module depuis le niveau de l'espace de nommage installe le module le plus récemment publié. Pour référencer une version spécifique d'un module dupliqué, utilisez le type de source [au niveau du projet](#from-a-project).

## Télécharger un module Terraform {#download-a-terraform-module}

Pour télécharger un module Terraform :

1. Dans la barre latérale gauche, sélectionnez **Opération** > **Modules Terraform**.
1. Sélectionnez le nom du module que vous souhaitez télécharger.
1. Dans le tableau **Ressources**, sélectionnez le module que vous souhaitez télécharger.

## Supprimer un module Terraform {#delete-a-terraform-module}

Vous ne pouvez pas modifier un module Terraform après l'avoir publié dans le Registre des modules Terraform. À la place, vous devez le supprimer et le recréer.

Vous pouvez supprimer des modules en utilisant [l'API des paquets](../../../api/packages.md#delete-a-project-package) ou l'interface utilisateur.

Pour supprimer un module dans l'interface utilisateur, depuis votre projet :

1. Dans la barre latérale gauche, sélectionnez **Opération** > **Modules Terraform**.
1. Trouvez le nom du paquet que vous souhaitez supprimer.
1. Sélectionnez **Supprimer**.

Le paquet est définitivement supprimé.

## Désactiver le Registre des modules Terraform {#disable-the-terraform-module-registry}

Le Registre des modules Terraform est automatiquement activé.

Pour les instances GitLab Self-Managed, un administrateur GitLab peut [désactiver](../../../administration/packages/_index.md#enable-or-disable-the-package-registry) **Paquets et registres**, ce qui supprime cet élément de menu de la barre latérale.

Vous pouvez également supprimer le Registre des modules Terraform pour un projet spécifique :

1. Dans votre projet, accédez à **Paramètres** > **Général**.
1. Développez la section **Visibilité, fonctionnalités du projet, autorisations** et désactivez **Paquet**.
1. Sélectionnez **Enregistrer les modifications**.

## Exemples de projets {#example-projects}

Pour des exemples du Registre des modules Terraform, consultez les projets ci-dessous :

- Le [projet _GitLab local file_](https://gitlab.com/mattkasa/gitlab-local-file) crée un module Terraform minimal et le charge dans le Registre des modules Terraform à l'aide de GitLab CI/CD.
- Le [projet _Terraform module test_](https://gitlab.com/mattkasa/terraform-module-test) utilise le module de l'exemple précédent.
