---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Dépannage de l'intégration Terraform avec GitLab"
---

Lorsque vous utilisez l'intégration avec Terraform et GitLab, vous pouvez rencontrer des problèmes nécessitant un dépannage.

## Ressources `gitlab_group_share_group` non détectées lors du rafraîchissement de l'état du sous-groupe {#gitlab_group_share_group-resources-not-detected-when-subgroup-state-is-refreshed}

Le fournisseur Terraform GitLab peut ne pas détecter les ressources `gitlab_group_share_group` existantes en raison du ticket [« L'utilisateur disposant des autorisations ne peut pas récupérer `share_with_groups` depuis l'API »](https://gitlab.com/gitlab-org/gitlab/-/issues/328428). Cela génère une erreur lors de l'exécution de `terraform apply`, car Terraform tente de recréer une ressource existante.

Par exemple, considérez la configuration de groupe/sous-groupe suivante :

```plaintext
parent-group
├── subgroup-A
└── subgroup-B
```

Où :

- L'utilisateur `user-1` crée `parent-group`, `subgroup-A` et `subgroup-B`.
- `subgroup-A` est partagé avec `subgroup-B`.
- L'utilisateur `terraform-user` est membre de `parent-group` avec un accès `owner` hérité aux deux sous-groupes.

Lors du rafraîchissement de l'état Terraform, la requête API `GET /groups/:subgroup-A_id` émise par le fournisseur ne retourne pas les détails de `subgroup-B` dans le tableau `shared_with_groups`. Cela provoque l'erreur.

Pour contourner ce problème, assurez-vous d'appliquer l'une des conditions suivantes :

1. L'utilisateur `terraform-user` crée toutes les ressources de sous-groupe.
1. Accordez le rôle Maintainer ou Owner à l'utilisateur `terraform-user` sur `subgroup-B`.
1. L'utilisateur `terraform-user` a hérité de l'accès à `subgroup-B` et `subgroup-B` contient au moins un projet.

## Dépannage de l'état Terraform {#troubleshooting-terraform-state}

### Impossible de verrouiller les fichiers d'état Terraform dans les jobs CI pour `terraform apply` avec le plan d'un job précédent {#cant-lock-terraform-state-files-in-ci-jobs-for-terraform-apply-with-a-previous-jobs-plan}

Lors du passage de `-backend-config=` à `terraform init`, Terraform conserve ces valeurs dans le fichier de cache du plan. Cela inclut la valeur `password`.

Par conséquent, pour créer un plan et l'utiliser ultérieurement dans un autre job CI, vous pourriez obtenir des erreurs `Error: Error acquiring the state lock` lors de l'utilisation de `-backend-config=password=$CI_JOB_TOKEN`. Cela se produit parce que la valeur de `$CI_JOB_TOKEN` n'est valide que pour la durée du job en cours.

Pour contourner ce problème, utilisez les [variables de configuration du backend HTTP](https://www.terraform.io/language/settings/backends/http#configuration-variables) dans votre job CI, ce qui correspond à ce qui se passe en coulisse lorsque vous suivez les instructions [Démarrer avec GitLab CI](terraform_state.md#initialize-an-opentofu-state-as-a-backend-by-using-gitlab-cicd).

### Erreur : `"address": required field is not set` {#error-address-required-field-is-not-set}

Par défaut, GitLab définit `TF_ADDRESS` sur `${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/terraform/state/${TF_STATE_NAME}`. Si vous ne définissez pas `TF_STATE_NAME` ou `TF_ADDRESS` dans votre job, le job échoue avec le message d'erreur `Error: "address": required field is not set`.

Pour résoudre ce problème, assurez-vous que `TF_ADDRESS` ou `TF_STATE_NAME` est accessible dans le job qui a retourné l'erreur :

1. Configurez la [portée d'environnement CI/CD](../../../ci/variables/_index.md#for-a-project) pour le job.
1. Définissez l'[environnement](../../../ci/yaml/_index.md#environment) du job, en faisant correspondre la portée d'environnement avec l'étape précédente.

### Erreur lors du rafraîchissement de l'état : le point de terminaison d'état HTTP distant nécessite une authentification {#error-refreshing-state-http-remote-state-endpoint-requires-auth}

Pour résoudre ce problème, assurez-vous que :

- Le jeton d'accès que vous utilisez possède la portée `api`.
- Si vous avez défini la variable CI/CD `TF_HTTP_PASSWORD`, assurez-vous de :
  - Définir la même valeur que `TF_PASSWORD`
  - Supprimer la variable `TF_HTTP_PASSWORD` si votre job CI/CD ne l'utilise pas explicitement.

### Autoriser le rôle Developer à exécuter des commandes destructives {#enable-developer-role-access-to-destructive-commands}

Pour autoriser un utilisateur disposant du rôle Developer à exécuter des commandes destructives, vous avez besoin d'une solution de contournement :

1. [Créez un jeton d'accès au projet](../../project/settings/project_access_tokens.md#create-a-project-access-token) avec la portée `api`.
1. Ajoutez `TF_USERNAME` et `TF_PASSWORD` à vos variables CI/CD :
   1. Définissez la valeur de `TF_USERNAME` sur le nom d'utilisateur de votre jeton d'accès au projet.
   1. Définissez la valeur de `TF_PASSWORD` sur le mot de passe de votre jeton d'accès au projet.
   1. Facultatif. Protégez les variables pour les rendre disponibles uniquement dans les pipelines qui s'exécutent sur des branches protégées ou des tags protégés.

### État introuvable si le nom d'état contient un point {#state-not-found-if-the-state-name-contains-a-period}

GitLab 15.6 et les versions antérieures retournaient des erreurs 404 si le nom d'état contenait un point et que Terraform tentait un verrouillage d'état.

Vous pouvez contourner cette limitation en ajoutant `-lock=false` à vos commandes Terraform. Le backend GitLab acceptait la requête, mais supprimait en interne le point et tous les caractères qui le suivaient dans le nom d'état. Par exemple, un état nommé `foo.bar` serait stocké sous le nom `foo`. Cependant, cette solution de contournement n'était pas recommandée et pouvait même provoquer des collisions de noms d'état.

Dans GitLab 15.7 et les versions ultérieures, [les noms d'état contenant des points sont pris en charge](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/106861). Si vous utilisez la solution de contournement `-lock=false` et que vous mettez à niveau vers GitLab 15.7 ou une version ultérieure, vos jobs pourraient échouer. L'échec est causé par le backend GitLab qui stocke un nouvel état avec le nom d'état complet, ce qui diverge du nom d'état existant.

Pour corriger les jobs défaillants, renommez vos noms d'état afin d'exclure le point et tous les caractères qui le suivent.

Si vos variables `TF_HTTP_ADDRESS`, `TF_HTTP_LOCK_ADDRESS` et `TF_HTTP_UNLOCK_ADDRESS` sont définies, veillez à mettre à jour les noms d'état à ces emplacements.

Vous pouvez également [migrer votre état OpenTofu](terraform_state.md#migrate-to-a-gitlab-managed-opentofu-state).

### Erreur lors de l'enregistrement de l'état : erreur HTTP : 404 {#error-saving-state-http-error-404}

Cette erreur peut survenir si le nom d'état inclut un caractère barre oblique (`/`). Pour résoudre ce problème, assurez-vous que le nom d'état ne contient aucun caractère barre oblique (`/`).
