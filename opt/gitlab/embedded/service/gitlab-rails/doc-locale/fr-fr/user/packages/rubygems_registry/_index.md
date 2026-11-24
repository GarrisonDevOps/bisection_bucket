---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Gems Ruby dans le registre de paquets
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/52147) dans GitLab 13.9 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `rubygem_packages`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est une [version expérimentale](../../../policy/development_stages_support.md).

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique. Cette fonctionnalité est disponible à des fins de test, mais n'est pas prête pour une utilisation en production.

Vous pouvez publier des gems Ruby dans le registre de paquets de votre projet. Vous pouvez ensuite les télécharger depuis l'interface utilisateur ou via l'API.

Cette fonctionnalité est une [version expérimentale](../../../policy/development_stages_support.md). Pour plus d'informations sur le développement de cette fonctionnalité, consultez [l'epic 3200](https://gitlab.com/groups/gitlab-org/-/work_items/3200).

## S'authentifier auprès du registre de paquets {#authenticate-to-the-package-registry}

Avant de pouvoir interagir avec le registre de paquets, vous devez vous y authentifier.

Pour ce faire, vous pouvez utiliser :

- Un [jeton d'accès personnel](../../profile/personal_access_tokens.md) avec la portée définie sur `api`.
- Un [jeton de déploiement](../../project/deploy_tokens/_index.md) avec la portée définie sur `read_package_registry`, `write_package_registry`, ou les deux.
- Un [jeton de job CI/CD](../../../ci/jobs/ci_job_token.md).

Par exemple :

{{< tabs >}}

{{< tab title="Avec un jeton d'accès" >}}

Pour s'authentifier avec un jeton d'accès :

- Créez ou modifiez votre fichier `~/.gem/credentials`, puis ajoutez :

  ```ini
  ---
  https://gitlab.example.com/api/v4/projects/<project_id>/packages/rubygems: '<token>'
  ```

Dans cet exemple :

- `<token>` doit correspondre à la valeur de votre jeton d'accès personnel ou de votre jeton de déploiement.
- `<project_id>` est affiché sur la [page de présentation du projet](../../project/working_with_projects.md#find-the-project-id).

{{< /tab >}}

{{< tab title="Avec un jeton de job CI/CD" >}}

Pour s'authentifier avec un jeton de job CI/CD :

- Créez ou modifiez votre fichier `.gitlab-ci.yml`, puis ajoutez :

  ```yaml
  # assuming a my_gem.gemspec file is present in the repository with the version currently set to 0.0.1
  image: ruby

  run:
    before_script:
      - mkdir ~/.gem
      - echo "---" > ~/.gem/credentials
      - |
        echo "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/rubygems: '${CI_JOB_TOKEN}'" >> ~/.gem/credentials
      - chmod 0600 ~/.gem/credentials # rubygems requires 0600 permissions on the credentials file
    script:
      - gem build my_gem
      - gem push my_gem-0.0.1.gem --host ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/rubygems
  ```

  Vous pouvez également utiliser `CI_JOB_TOKEN` dans un fichier `~/.gem/credentials` que vous intégrez à GitLab :

  ```ini
  ---
  https://gitlab.example.com/api/v4/projects/${env.CI_PROJECT_ID}/packages/rubygems: '${env.CI_JOB_TOKEN}'
  ```

{{< /tab >}}

{{< /tabs >}}

## Pousser un gem Ruby {#push-a-ruby-gem}

Prérequis :

- Vous devez [vous authentifier auprès du registre de paquets](#authenticate-to-the-package-registry).
- Votre gem Ruby doit être de 3 Go ou moins.

Pour cela :

- Exécutez une commande telle que :

  ```shell
  gem push my_gem-0.0.1.gem --host <host>
  ```

  Dans cet exemple, `<host>` est l'URL que vous avez utilisée lors de la configuration de l'authentification. Par exemple :

  ```shell
  gem push my_gem-0.0.1.gem --host https://gitlab.example.com/api/v4/projects/1/packages/rubygems
  ```

Lorsqu'un gem est publié avec succès, un message similaire à celui-ci s'affiche :

```plaintext
Pushing gem to https://gitlab.example.com/api/v4/projects/1/packages/rubygems...
{"message":"201 Created"}
```

Le gem est publié dans votre registre de paquets et apparaît sur la page **Paquets et registres**. GitLab peut mettre jusqu'à 10 minutes pour traiter et afficher votre gem.

### Pousser des gems avec le même nom ou la même version {#pushing-gems-with-the-same-name-or-version}

Vous pouvez pousser un gem même si un paquet portant le même nom et la même version existe déjà. Les deux sont visibles et accessibles dans l'interface utilisateur.

## Supprimer un gem Ruby {#delete-a-ruby-gem}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire.

Avant de supprimer un paquet, assurez-vous de comprendre les [risques de sécurité associés](../package_registry/supported_functionality.md#deleting-packages).

Pour supprimer un paquet, vous pouvez :

- [Utiliser l'interface utilisateur](../package_registry/reduce_package_registry_storage.md#delete-a-package).
- [Utiliser l'API](../../../api/packages.md#delete-a-project-package).

## Installer un gem Ruby {#install-a-ruby-gem}

Prérequis :

- Vous devez [vous authentifier auprès du registre de paquets](#authenticate-to-the-package-registry).

Pour installer un gem, transmettez vos identifiants dans l'URL source sous forme d'authentification HTTP Basic. Utilisez `__token__` comme nom d'utilisateur et votre jeton d'accès personnel, jeton de déploiement ou jeton de job CI/CD comme mot de passe.

Dans les exemples suivants :

- `<token>` est votre jeton d'accès personnel, votre jeton de déploiement ou votre jeton de job CI/CD.
- `<project_id>` est affiché sur la [page de présentation du projet](../../project/working_with_projects.md#find-the-project-id).

{{< tabs >}}

{{< tab title="Avec la commande gem" >}}

Exécutez une commande telle que :

```shell
gem install my_gem --source "https://__token__:<token>@gitlab.example.com/api/v4/projects/<project_id>/packages/rubygems"
```

{{< /tab >}}

{{< tab title="Avec Bundler" >}}

Dans votre `Gemfile`, ajoutez un bloc `source` :

```ruby
source "https://__token__:<token>@gitlab.example.com/api/v4/projects/<project_id>/packages/rubygems" do
  gem "my_gem"
end
```

{{< /tab >}}

{{< /tabs >}}

## Télécharger un fichier gem {#download-a-gem-file}

Pour télécharger un fichier gem en vue d'une utilisation locale sans l'installer :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Registre de paquets**.
1. Sélectionnez le nom et la version du paquet.
1. Sous **Ressources**, sélectionnez le gem Ruby que vous souhaitez télécharger.

Pour télécharger un fichier gem, vous pouvez également [utiliser l'API](../../../api/packages/rubygems.md#download-a-gem-file).

## Sujets connexes {#related-topics}

- [Créer votre propre gem](https://guides.rubygems.org/make-your-own-gem/)
- [Documentation de l'API Ruby gems](../../../api/packages/rubygems.md)
