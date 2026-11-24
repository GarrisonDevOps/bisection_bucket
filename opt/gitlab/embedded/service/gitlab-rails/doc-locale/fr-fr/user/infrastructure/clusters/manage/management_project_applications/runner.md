---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Installer GitLab Runner avec un projet de gestion de cluster
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

En supposant que vous ayez déjà un projet créé à partir d'un [modèle de projet de gestion](../../../../clusters/management_project_template.md), pour installer GitLab Runner, vous devez décommenter cette ligne de votre `helmfile.yaml` :

```yaml
  - path: applications/gitlab-runner/helmfile.yaml
```

GitLab Runner est installé par défaut dans l'espace de nommage `gitlab-managed-apps` de votre cluster.

## Variables requises {#required-variables}

Pour que GitLab Runner fonctionne, vous devez spécifier les éléments suivants dans votre fichier `applications/gitlab-runner/values.yaml.gotmpl` :

- `gitlabUrl` : L'URL complète du serveur GitLab (par exemple, `https://gitlab.example.com`) auprès de laquelle enregistrer le runner.
- Jeton du runner : celui-ci doit être [récupéré](../../../../../ci/runners/_index.md) depuis votre instance GitLab. Vous pouvez utiliser l'un des jetons suivants :

  - `runnerToken` : le jeton d'authentification du runner pour la configuration du runner [créée dans l'interface utilisateur GitLab](../../../../../ci/runners/runners_scope.md).
  - `runnerRegistrationToken` ([déprécié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/102681) dans GitLab 15.6 et dont la suppression est prévue dans GitLab 20.0.) : le jeton d'enregistrement utilisé pour ajouter de nouveaux runners à GitLab.

Ces valeurs peuvent être spécifiées à l'aide de [variables CI/CD](../../../../../ci/variables/_index.md) :

- `CI_SERVER_URL` est utilisé pour `gitlabUrl`. Si vous utilisez GitLab.com, vous n'avez pas besoin de définir cette variable CI/CD.
- `GITLAB_RUNNER_TOKEN` est utilisé pour `runnerToken`.
- `GITLAB_RUNNER_REGISTRATION_TOKEN` est utilisé pour `runnerRegistrationToken` (déprécié).

Les méthodes de spécification de ces valeurs sont mutuellement exclusives. Vous pouvez choisir l'une des deux options suivantes :

- Spécifiez les variables CI/CD `GITLAB_RUNNER_TOKEN` et `CI_SERVER_URL` comme variables CI (recommandé).
- Fournissez des valeurs pour `runnerToken:` et `gitlabUrl:` dans `applications/gitlab-runner/values.yaml.gotmpl`.

Le jeton d'enregistrement du runner permet la connexion à un projet par un runner. Traitez-le comme un secret pour éviter toute utilisation malveillante et toute exfiltration de code via un runner. Spécifiez le jeton d'enregistrement du runner en tant que [variable protégée](../../../../../ci/variables/_index.md#protect-a-cicd-variable) et [variable masquée](../../../../../ci/variables/_index.md#mask-a-cicd-variable). Ne commitez pas les jetons dans le dépôt Git dans le fichier `values.yaml.gotmpl`.

Vous pouvez personnaliser l'installation de GitLab Runner en définissant le fichier `applications/gitlab-runner/values.yaml.gotmpl` dans votre projet de gestion de cluster. Référez-vous au [chart](https://gitlab.com/gitlab-org/charts/gitlab-runner) pour les options de configuration disponibles.
