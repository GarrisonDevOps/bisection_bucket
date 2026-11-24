---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Harbor
description: Configurez Harbor comme registre de conteneurs open source pour votre projet GitLab afin de gérer les artefacts sur différentes plateformes.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez utiliser Harbor comme registre de conteneurs pour votre projet GitLab.

[Harbor](https://goharbor.io/) est un registre open source qui vous aide à gérer les artefacts sur des plateformes de calcul cloud-native comme Kubernetes et Docker.

L'intégration Harbor peut vous aider si vous avez besoin de GitLab CI/CD et d'un dépôt d'images de conteneurs.

## Prérequis {#prerequisites}

Dans l'instance Harbor, assurez-vous que :

- Le projet à intégrer a été créé.
- L'utilisateur authentifié dispose des autorisations pour extraire, envoyer et modifier des images dans le projet Harbor.

## Configurer GitLab {#configure-gitlab}

GitLab prend en charge l'intégration des projets Harbor au niveau du groupe ou du projet. Effectuez ces étapes dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Harbor**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Renseignez les informations de configuration Harbor :
   - **URL de Harbor** : L'URL de base de l'instance Harbor qui est liée à ce projet GitLab. Par exemple, `https://harbor.example.net`.
   - **Nom du projet Harbor** : le nom du projet dans l'instance Harbor. Par exemple, `testproject`.
   - **Nom d'utilisateur** : votre nom d'utilisateur dans l'instance Harbor, qui doit répondre aux exigences indiquées dans [les prérequis](#prerequisites).
   - **Mot de passe** : mot de passe associé à votre nom d'utilisateur.

1. Sélectionnez **Enregistrer les modifications**.

Une fois l'intégration Harbor activée :

- Les variables globales `$HARBOR_USERNAME`, `$HARBOR_HOST`, `$HARBOR_OCI`, `$HARBOR_PASSWORD`, `$HARBOR_URL` et `$HARBOR_PROJECT` sont créées pour une utilisation CI/CD.
- Les paramètres d'intégration au niveau du projet remplacent les paramètres d'intégration au niveau du groupe.

## Considérations relatives à la sécurité {#security-considerations}

### Sécuriser vos requêtes vers les API Harbor {#secure-your-requests-to-the-harbor-apis}

Pour chaque requête API effectuée via l'intégration Harbor, les identifiants de connexion à l'API Harbor utilisent la combinaison `username:password`. Voici quelques suggestions pour une utilisation sécurisée :

- Utilisez TLS sur les API Harbor auxquelles vous vous connectez.
- Appliquez le principe du moindre privilège (pour l'accès sur Harbor) avec vos identifiants.
- Mettez en place une politique de rotation de vos identifiants.

### Sécurité des variables CI/CD {#cicd-variable-security}

Du code malveillant envoyé dans votre fichier `.gitlab-ci.yml` pourrait compromettre vos variables, notamment `$HARBOR_PASSWORD`, et les transmettre à un serveur tiers. Pour plus de détails, consultez [Sécurité des variables CI/CD](../../../ci/variables/_index.md#cicd-variable-security).

## Utiliser les variables Harbor {#use-harbor-variables}

### Envoyer un chart Helm avec un registre OCI {#push-a-helm-chart-with-an-oci-registry}

Helm prend en charge les registres OCI par défaut. OCI est pris en charge dans [Harbor 2.0](https://github.com/goharbor/harbor/releases/tag/v2.0.0) et les versions ultérieures. Pour en savoir plus sur OCI, consultez le [blog](https://helm.sh/blog/storing-charts-in-oci/) et la [documentation](https://helm.sh/docs/topics/registries/#enabling-oci-support) de Helm.

```yaml
helm:
  stage: helm
  image:
    name: dtzar/helm-kubectl:latest
    entrypoint: ['']
  variables:
    # Enable OCI support (not required since Helm v3.8.0)
    HELM_EXPERIMENTAL_OCI: 1
  script:
    # Log in to the Helm registry
    - helm registry login "${HARBOR_URL}" -u "${HARBOR_USERNAME}" -p "${HARBOR_PASSWORD}"
    # Package your Helm chart, which is in the `test` directory
    - helm package test
    # Your helm chart is created with <chart name>-<chart release>.tgz
    # You can push all building charts to your Harbor repository
    - helm push test-*.tgz ${HARBOR_OCI}/${HARBOR_PROJECT}
```
