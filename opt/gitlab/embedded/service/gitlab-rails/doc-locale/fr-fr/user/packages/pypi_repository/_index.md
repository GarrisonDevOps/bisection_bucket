---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Paquets PyPI dans le registre de paquets
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Le Python Package Index (PyPI) est le dépôt officiel de logiciels tiers pour Python. Utilisez le registre de paquets PyPI de GitLab pour publier et partager des paquets Python dans vos projets, groupes et organisations GitLab. Cette intégration vous permet de gérer vos dépendances Python aux côtés de votre code, offrant un workflow fluide pour le développement Python dans GitLab.

Le registre de paquets fonctionne avec :

- [pip](https://pypi.org/project/pip/)
- [twine](https://pypi.org/project/twine/)

Pour la documentation des endpoints API spécifiques utilisés par les clients `pip` et `twine`, consultez la [documentation de l'API PyPI](../../../api/packages/pypi.md).

Découvrez comment [créer un paquet PyPI](../workflows/build_packages.md#pypi).

## Avis de sécurité sur le transfert des demandes de paquets {#package-request-forwarding-security-notice}

Lors de l'utilisation du registre de paquets PyPI de GitLab, les demandes de paquets introuvables dans le registre GitLab sont automatiquement transférées vers `pypi.org`. Ce comportement peut entraîner le téléchargement de paquets depuis `pypi.org`, même lors de l'utilisation du flag `--index-url`.

Pour une sécurité maximale lors de l'utilisation de paquets privés :

- Désactivez le transfert de paquets dans les paramètres de votre groupe.
- Utilisez les deux flags [`--index-url` et `--no-index`](#security-implications) lors de l'installation des paquets.

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.

Pour désactiver le transfert des demandes de paquets :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Sous **Transfert de paquet**, décochez la case **Transférer les demandes de paquets PyPI**.

Pour savoir comment désactiver le transfert de paquets dans la zone **Admin**, consultez [Contrôler le transfert de paquets](../../../administration/settings/continuous_integration.md#control-package-forwarding).

## S'authentifier auprès du registre de paquets GitLab {#authenticate-with-the-gitlab-package-registry}

Avant d'interagir avec le registre de paquets GitLab, vous devez vous y authentifier.

Vous pouvez vous authentifier avec :

- Un [jeton d'accès personnel](../../profile/personal_access_tokens.md) avec la portée définie sur `api`.
- Un [jeton de déploiement](../../project/deploy_tokens/_index.md) avec la portée définie sur `read_package_registry`, `write_package_registry`, ou les deux.
- Un [jeton de job CI/CD](../../../ci/jobs/ci_job_token.md).

N'utilisez pas de méthodes d'authentification autres que celles documentées ici. Les méthodes d'authentification non documentées pourraient être supprimées à l'avenir.

Pour vous authentifier avec un jeton GitLab :

- Mettez à jour les variables d'environnement `TWINE_USERNAME` et `TWINE_PASSWORD`.

Par exemple :

{{< tabs >}}

{{< tab title="Avec un jeton d'accès personnel" >}}

```yaml
run:
  image: python:latest
  variables:
    TWINE_USERNAME: <personal_access_token_name>
    TWINE_PASSWORD: <personal_access_token>
  script:
    - pip install build twine
    - python -m build
    - python -m twine upload --repository-url ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/pypi dist/*
```

{{< /tab >}}

{{< tab title="Avec un jeton de déploiement" >}}

```yaml
run:
  image: python:latest
  variables:
    TWINE_USERNAME: <deploy_token_username>
    TWINE_PASSWORD: <deploy_token>
  script:
    - pip install build twine
    - python -m build
    - python -m twine upload --repository-url ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/pypi dist/*
```

{{< /tab >}}

{{< tab title="Avec un jeton de job CI/CD" >}}

```yaml
run:
  image: python:latest
  variables:
    TWINE_USERNAME: gitlab-ci-token
    TWINE_PASSWORD: $CI_JOB_TOKEN
  script:
    - pip install build twine
    - python -m build
    - python -m twine upload --repository-url ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/pypi dist/*
```

{{< /tab >}}

{{< /tabs >}}

### S'authentifier pour un groupe {#authenticate-for-a-group}

Pour vous authentifier auprès du registre de paquets pour un groupe :

- Authentifiez-vous auprès du registre de paquets, mais utilisez l'URL du groupe à la place de l'URL du projet :

```shell
https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/pypi
```

## Publier un paquet PyPI {#publish-a-pypi-package}

Vous pouvez publier un paquet avec twine.

Prérequis :

- Vous devez [vous authentifier auprès du registre de paquets](#authenticate-with-the-gitlab-package-registry).
- Votre [chaîne de version doit être valide](#use-valid-version-strings).
- Le paquet :
  - Est de 5 Go ou moins.
  - A une `description` de 4000 caractères ou moins. Les chaînes `description` plus longues sont tronquées.
  - N'est pas déjà publié dans le registre de paquets. Toute tentative de publier la même version d'un paquet renvoie `400 Bad Request`.

Les paquets PyPI sont publiés à l'aide de l'ID de votre projet. Si votre projet est dans un groupe, les paquets PyPI publiés dans le registre de paquets du projet sont également disponibles dans le registre de paquets du groupe. Pour plus d'informations, consultez [Installer depuis un groupe](#install-from-a-group).

Pour publier un paquet :

1. Définissez la source de votre dépôt, modifiez le fichier `~/.pypirc` et ajoutez :

   ```ini
   [distutils]
   index-servers =
       gitlab

   [gitlab]
   repository = https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi
   ```

1. Chargez votre paquet avec twine :

   ```shell
   python3 -m twine upload --repository gitlab dist/*
   ```

   Lorsqu'un paquet est publié avec succès, un message similaire à celui-ci s'affiche :

   ```plaintext
   Uploading distributions to https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi
   Uploading mypypipackage-0.0.1-py3-none-any.whl
   100%|███████████████████████████████████████████████████████████████████████████████████████████| 4.58k/4.58k [00:00<00:00, 10.9kB/s]
   Uploading mypypipackage-0.0.1.tar.gz
   100%|███████████████████████████████████████████████████████████████████████████████████████████| 4.24k/4.24k [00:00<00:00, 11.0kB/s]
   ```

Le paquet est publié dans le registre de paquets et s'affiche sur la page **Paquets et registres**.

### Publier avec une authentification inline {#publish-with-inline-authentication}

Si vous n'avez pas utilisé de fichier `.pypirc` pour définir la source de votre dépôt, vous pouvez publier dans le dépôt avec une authentification inline :

```shell
TWINE_PASSWORD=<personal_access_token, deploy_token, or $CI_JOB_TOKEN> \
TWINE_USERNAME=<username, deploy_token_username, or gitlab-ci-token> \
python3 -m twine upload --repository-url https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi dist/*
```

### Publication de paquets avec le même nom et la même version {#publishing-packages-with-the-same-name-and-version}

Vous ne pouvez pas publier un paquet si un paquet portant le même nom et la même version existe déjà. Vous devez d'abord [supprimer le paquet existant](../package_registry/reduce_package_registry_storage.md#delete-a-package). Si vous tentez de publier le même paquet plus d'une fois, une erreur `400 Bad Request` se produit.

## Installer un paquet PyPI {#install-a-pypi-package}

Par défaut, lorsqu'un paquet PyPI est introuvable dans le registre de paquets GitLab, la demande est transférée vers [pypi.org](https://pypi.org/). Pour plus d'informations sur la façon d'empêcher le transfert des demandes, consultez [l'avis de sécurité sur le transfert des demandes de paquets](#package-request-forwarding-security-notice).

Ce comportement :

- Est activé par défaut pour toutes les instances GitLab
- Peut être configuré dans les paramètres **Paquets et registres** du groupe
- S'applique même lors de l'utilisation du flag `--index-url`

Les administrateurs peuvent désactiver ce comportement globalement dans les [paramètres d'intégration continue](../../../administration/settings/continuous_integration.md#control-package-forwarding). Les propriétaires de groupes peuvent désactiver ce comportement pour des groupes spécifiques dans la section **Paquets et registres** des paramètres du groupe.

> [!note]
> Lorsque vous utilisez l'option `--index-url`, ne spécifiez pas le port s'il s'agit d'un port par défaut. Les URL `http` utilisent le port 80 par défaut, et les URL `https` utilisent le port 443 par défaut.

### Installer depuis un projet {#install-from-a-project}

Pour installer la dernière version d'un paquet, utilisez la commande suivante :

```shell
pip install --index-url https://<personal_access_token_name>:<personal_access_token>@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple --no-deps <package_name>
```

- `<package_name>` est le nom du paquet.
- `<personal_access_token_name>` est un nom de jeton d'accès personnel avec la portée `read_api`.
- `<personal_access_token>` est un jeton d'accès personnel avec la portée `read_api`.
- `<project_id>` est soit le chemin [encodé dans l'URL](../../../api/rest/_index.md#namespaced-paths) du projet (par exemple, `group%2Fproject`), soit l'ID du projet (par exemple `42`).

Dans ces commandes, vous pouvez utiliser `--extra-index-url` à la place de `--index-url`. Si vous suivez le guide et souhaitez installer le paquet `MyPyPiPackage`, vous pouvez exécuter :

```shell
pip install mypypipackage --no-deps --index-url https://<personal_access_token_name>:<personal_access_token>@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
```

Ce message indique que le paquet a été installé avec succès :

```plaintext
Looking in indexes: https://<personal_access_token_name>:****@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
Collecting mypypipackage
  Downloading https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/files/d53334205552a355fee8ca35a164512ef7334f33d309e60240d57073ee4386e6/mypypipackage-0.0.1-py3-none-any.whl (1.6 kB)
Installing collected packages: mypypipackage
Successfully installed mypypipackage-0.0.1
```

### Installer depuis un groupe {#install-from-a-group}

Pour installer la dernière version d'un paquet depuis un groupe, utilisez la commande suivante :

```shell
pip install --index-url https://<personal_access_token_name>:<personal_access_token>@gitlab.example.com/api/v4/groups/<group_id>/-/packages/pypi/simple --no-deps <package_name>
```

Dans cette commande :

- `<package_name>` est le nom du paquet.
- `<personal_access_token_name>` est un nom de jeton d'accès personnel avec la portée `read_api`.
- `<personal_access_token>` est un jeton d'accès personnel avec la portée `read_api`.
- `<group_id>` est l'ID du groupe.

Dans ces commandes, vous pouvez utiliser `--extra-index-url` à la place de `--index-url`. Si vous suivez le guide et souhaitez installer le paquet `MyPyPiPackage`, vous pouvez exécuter :

```shell
pip install mypypipackage --no-deps --index-url https://<personal_access_token_name>:<personal_access_token>@gitlab.example.com/api/v4/groups/<group_id>/-/packages/pypi/simple
```

### Noms des paquets {#package-names}

GitLab recherche les paquets qui utilisent les [noms normalisés Python (PEP-503)](https://www.python.org/dev/peps/pep-0503/#normalized-names). Les caractères `-`, `_` et `.` sont tous traités de la même façon, et les caractères répétés sont supprimés.

Une demande `pip install` pour `my.package` recherche les paquets correspondant à l'un des trois caractères, tels que `my-package`, `my_package` et `my....package`.

### Implications en matière de sécurité {#security-implications}

Les implications en matière de sécurité liées à l'utilisation de `--extra-index-url` par rapport à `--index-url` lors de l'installation de paquets PyPI sont significatives et méritent d'être bien comprises :

- `--index-url` : cette option remplace l'URL d'index PyPI par défaut par l'URL spécifiée. Le paramètre de transfert de paquets GitLab, activé par défaut, peut toujours télécharger depuis PyPI des paquets introuvables dans le registre de paquets. Pour garantir que les paquets sont installés uniquement depuis GitLab, vous pouvez :
  - Désactiver le transfert de paquets dans les paramètres du groupe
  - Utiliser les deux flags `--index-url` et `--no-index` ensemble
- `--extra-index-url` : cette option ajoute un index supplémentaire à rechercher, en plus de l'index PyPI par défaut. Elle est moins sécurisée et plus vulnérable aux attaques par confusion de dépendances, car elle vérifie les paquets à la fois dans l'index PyPI par défaut et dans l'index supplémentaire.

Lors de l'utilisation de paquets privés, gardez à l'esprit les bonnes pratiques suivantes :

- Vérifiez les paramètres de transfert de paquets de votre groupe.
- Utilisez les flags `--no-index` et `--index-url` ensemble lors de l'installation de paquets privés.
- Auditez régulièrement vos sources de paquets à l'aide de `pip debug`.

## Supprimer un paquet PyPI {#delete-a-pypi-package}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire.

Avant de supprimer un paquet, assurez-vous de bien comprendre les [risques de sécurité associés](../package_registry/supported_functionality.md#deleting-packages).

Pour supprimer un paquet, vous pouvez :

- [Utiliser l'interface utilisateur](../package_registry/reduce_package_registry_storage.md#delete-a-package).
- [Utiliser l'API](../../../api/packages.md#delete-a-project-package).

## Installer un paquet PyPI privé dans un pipeline CI/CD {#install-a-private-pypi-package-in-a-cicd-pipeline}

Vous pouvez installer des paquets PyPI privés dans des pipelines CI/CD à l'aide d'un [jeton de job CI/CD](../../../ci/jobs/ci_job_token.md). Le jeton de job s'authentifie automatiquement et peut également accéder aux paquets d'autres projets au sein du même groupe principal.

Prérequis :

- Si le paquet se trouve dans un projet différent, ce projet doit autoriser les jetons de job de votre projet. Pour plus d'informations, consultez [Contrôler l'accès aux jetons de job](../../../ci/jobs/ci_job_token.md#control-job-token-access-to-your-project).
- Lors de l'authentification avec un jeton de job CI/CD, le nom d'utilisateur doit être `gitlab-ci-token`.

### Utiliser des identifiants inline {#use-inline-credentials}

Transmettez le `CI_JOB_TOKEN` directement dans la commande `pip install` :

{{< tabs >}}

{{< tab title="Depuis un projet" >}}

```yaml
install:
  image: python:latest
  script:
    - pip install <package_name> --index-url https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
```

{{< /tab >}}

{{< tab title="Depuis un groupe" >}}

Pour installer depuis un index de groupe, qui inclut les paquets de tous les projets du groupe :

```yaml
install:
  image: python:latest
  script:
    - pip install <package_name> --index-url https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.example.com/api/v4/groups/<group_id>/-/packages/pypi/simple
```

{{< /tab >}}

{{< /tabs >}}

### Utiliser un fichier `.netrc` pour CI/CD {#use-a-netrc-file-for-cicd}

`.netrc` maintient votre fichier `requirements.txt` sans identifiants, ce qui permet au même fichier de fonctionner aussi bien localement que dans les pipelines CI/CD. pip lit automatiquement le fichier `.netrc` pour trouver les identifiants d'un nom d'hôte donné. Pour plus d'informations, consultez [la prise en charge de .netrc](https://pip.pypa.io/en/stable/topics/authentication/#netrc-support).

Dans votre `.gitlab-ci.yml`, créez le fichier `.netrc` dans `before_script` :

```yaml
install:
  image: python:latest
  before_script:
    - |
      echo "machine gitlab.example.com
      login gitlab-ci-token
      password ${CI_JOB_TOKEN}" > ~/.netrc
  script:
    - pip install -r requirements.txt
```

Votre fichier `requirements.txt` référence le registre GitLab sans identifiants :

```plaintext
--extra-index-url https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
package-name==1.0.0
```

Pour le développement local, créez un fichier `~/.netrc` avec un [jeton d'accès personnel](../../profile/personal_access_tokens.md) ayant la portée `api` :

```plaintext
machine gitlab.example.com
login <personal_access_token_name>
password <personal_access_token>
```

> [!note]
> Le fichier `.netrc` configure un ensemble d'identifiants par nom d'hôte. Si vous devez vous authentifier avec des paquets sur plusieurs instances GitLab, ajoutez une entrée `machine` distincte pour chaque nom d'hôte.

### Installer des paquets privés lors d'un build Docker {#install-private-packages-during-a-docker-build}

Lors de la création d'images Docker nécessitant des paquets PyPI privés, transmettez le `CI_JOB_TOKEN` en tant qu'argument de build :

```yaml
build:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build --build-arg CI_JOB_TOKEN=$CI_JOB_TOKEN -t my-image .
```

Dans votre `Dockerfile`, utilisez le jeton pour vous authentifier auprès du registre :

```dockerfile
ARG CI_JOB_TOKEN
RUN pip install <package_name> --index-url https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
```

> [!note]
> Les arguments de build peuvent être visibles dans l'historique de l'image. Pour les images de production, utilisez des [builds multi-étapes](https://docs.docker.com/build/building/multi-stage/) afin que le jeton ne soit pas présent dans la couche finale de l'image.

## Utilisation de `requirements.txt` {#using-requirementstxt}

Si vous souhaitez que pip accède à votre registre public, ajoutez le paramètre `--extra-index-url` ainsi que l'URL de votre registre dans votre fichier `requirements.txt`.

```plaintext
--extra-index-url https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
package-name==1.0.0
```

S'il s'agit d'un registre privé, vous pouvez vous authentifier de plusieurs façons. Par exemple :

- En utilisant votre fichier `requirements.txt` avec un [jeton d'accès personnel](../../profile/personal_access_tokens.md) :

  ```plaintext
  --extra-index-url https://<personal_access_token_name>:<personal_access_token>@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
  package-name==1.0.0
  ```

- En utilisant un fichier `~/.netrc` avec un [jeton d'accès personnel](../../profile/personal_access_tokens.md) :

  ```plaintext
  machine gitlab.example.com
  login <personal_access_token_name>
  password <personal_access_token>
  ```

## Gestion des versions des paquets PyPI {#versioning-pypi-packages}

Une gestion correcte des versions est importante pour gérer efficacement les paquets PyPI. Suivez ces bonnes pratiques pour vous assurer que vos paquets sont versionnés correctement.

### Utiliser la gestion sémantique de version (SemVer) {#use-semantic-versioning-semver}

Adoptez la gestion sémantique de version pour vos paquets. Le numéro de version doit être au format `MAJOR.MINOR.PATCH` :

- Incrémentez la version `MAJOR` pour les changements d'API incompatibles.
- Incrémentez la version `MINOR` pour les nouvelles fonctionnalités rétrocompatibles.
- Incrémentez la version `PATCH` pour les corrections de bogues rétrocompatibles.

Par exemple : 1.0.0, 1.1.0, 1.1.1.

Pour les nouveaux projets, commencez avec la version 0.1.0. Cela indique une phase de développement initiale où l'API n'est pas encore stable.

### Utiliser des chaînes de version valides {#use-valid-version-strings}

Assurez-vous que votre chaîne de version est valide selon les normes PyPI. GitLab utilise une expression rationnelle spécifique pour valider les chaînes de version :

```ruby
\A(?:
    v?
    (?:([0-9]+)!)?                                                 (?# epoch)
    ([0-9]+(?:\.[0-9]+)*)                                          (?# release segment)
    ([-_\.]?((a|b|c|rc|alpha|beta|pre|preview))[-_\.]?([0-9]+)?)?  (?# pre-release)
    ((?:-([0-9]+))|(?:[-_\.]?(post|rev|r)[-_\.]?([0-9]+)?))?       (?# post release)
    ([-_\.]?(dev)[-_\.]?([0-9]+)?)?                                (?# dev release)
    (?:\+([a-z0-9]+(?:[-_\.][a-z0-9]+)*))?                         (?# local version)
)\z}xi
```

Vous pouvez expérimenter avec l'expression rationnelle et tester vos chaînes de version à l'aide de cet [éditeur d'expressions rationnelles](https://rubular.com/r/FKM6d07ouoDaFV).

Pour plus de détails sur l'expression rationnelle, consultez la [documentation Python](https://www.python.org/dev/peps/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions).

## Commandes CLI prises en charge {#supported-cli-commands}

Le dépôt PyPI de GitLab prend en charge les commandes CLI suivantes :

- `twine upload` : charger un paquet dans le registre.
- `pip install` : installer un paquet PyPI depuis le registre.

## Dépannage {#troubleshooting}

Pour améliorer les performances, la commande pip met en cache les fichiers liés à un paquet. Pip ne supprime pas les données par lui-même. Le cache augmente à mesure que de nouveaux paquets sont installés. Si vous rencontrez des problèmes, videz le cache avec cette commande :

```shell
pip cache purge
```

### Paramètres `index-url` ou `extra-index-url` multiples {#multiple-index-url-or-extra-index-url-parameters}

Vous pouvez définir plusieurs paramètres `index-url` et `extra-index-url`.

Si vous utilisez le même nom de domaine (tel que `gitlab.example.com`) plusieurs fois avec différents jetons d'authentification, `pip` peut ne pas être en mesure de trouver vos paquets. Ce problème est dû à la façon dont `pip` [enregistre et stocke vos jetons](https://github.com/pypa/pip/pull/10904#issuecomment-1126690115) lors de l'exécution des commandes.

Pour contourner ce problème, vous pouvez utiliser un [jeton de déploiement de groupe](../../project/deploy_tokens/_index.md) avec la portée `read_package_registry` depuis un groupe parent commun pour tous les projets ou groupes ciblés par les valeurs `index-url` et `extra-index-url`.

### Sources de paquets inattendues {#unexpected-package-sources}

Si des paquets sont installés depuis PyPI alors que vous souhaitiez utiliser uniquement le registre GitLab :

- Vérifiez les paramètres de transfert de paquets de votre groupe.
- Utilisez les flags `--no-index` et `--index-url` ensemble pour empêcher le recours à PyPI en solution de repli.
- Auditez régulièrement vos sources de paquets à l'aide de `pip debug`.
