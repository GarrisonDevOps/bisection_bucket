---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Jetons de déploiement
description: "Clonage de dépôt, création de jetons et registre de conteneurs."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les jetons de déploiement offrent un accès sécurisé aux ressources GitLab sans lier les permissions à des comptes utilisateurs individuels. Utilisez-les avec les opérations Git, les registres de conteneurs et les registres de paquets, en donnant à votre automatisation de déploiement accès exactement à ce dont elle a besoin.

Avec les jetons de déploiement, vous bénéficiez :

- De déploiements plus sécurisés en supprimant les identifiants personnels des systèmes d'automatisation
- D'un contrôle d'accès précis avec des permissions spécifiques pour chaque jeton
- De pipelines CI/CD simplifiés avec des variables d'authentification intégrées
- De processus de déploiement fiables qui ne seront pas interrompus lors de changements dans l'équipe
- De meilleures pistes d'audit grâce au suivi des déploiements via des identités de jetons dédiées
- D'une intégration transparente avec les systèmes de build externes et les outils de déploiement

Un jeton de déploiement est une paire de valeurs :

- **nom_d_utilisateur** : `username` dans le framework d'authentification HTTP. Le format de nom d'utilisateur par défaut est `gitlab+deploy-token-{n}`. Vous pouvez spécifier un nom d'utilisateur personnalisé lors de la création du jeton de déploiement.
- **jeton** : `password` dans le framework d'authentification HTTP.

Les jetons de déploiement ne prennent pas en charge [l'authentification SSH](../../ssh.md).

Vous pouvez utiliser un jeton de déploiement pour l'[authentification HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Authentication) aux endpoints suivants :

- API publique du registre de paquets GitLab.
- [Commandes Git](https://git-scm.com/docs/gitcredentials#_description).
- [Opérations sur les paquets du registre virtuel GitLab](../../../api/maven_virtual_registries.md#manage-package-operations).

Vous pouvez créer des jetons de déploiement au niveau d'un projet ou d'un groupe :

- **Jeton de déploiement de projet** : les permissions s'appliquent uniquement au projet.
- **Jeton de déploiement de groupe** : les permissions s'appliquent à tous les projets du groupe.

Par défaut, un jeton de déploiement n'expire pas. Vous pouvez éventuellement définir une date d'expiration lors de sa création. L'expiration survient à minuit UTC à cette date.

> [!warning]
> Vous ne pouvez pas utiliser de jetons de déploiement nouveaux ou existants pour les opérations Git et les opérations du registre de paquets si [l'autorisation externe](../../../administration/settings/external_authorization.md) est activée.

## Portée {#scope}

La portée d'un jeton de déploiement détermine les actions qu'il peut effectuer.

| Portée                    | Description                                                                                                  |
|--------------------------|--------------------------------------------------------------------------------------------------------------|
| `read_repository`        | Accès en lecture seule au dépôt en utilisant `git clone`.                                                        |
| `read_registry`          | Accès en lecture seule aux images dans le [registre de conteneurs](../../packages/container_registry/_index.md) du projet. |
| `write_registry`         | Accès en écriture (push) vers le [registre de conteneurs](../../packages/container_registry/_index.md) du projet. Vous avez besoin d'un accès en lecture et en écriture pour envoyer des images. |
| `read_virtual_registry`  | Accorde un accès en lecture seule (pull) aux images de conteneurs via le proxy de dépendances et le registre virtuel au niveau du groupe. N'accorde pas d'accès direct au registre de conteneurs du projet. Disponible uniquement lorsque le proxy de dépendances est activé. |
| `write_virtual_registry` | Accorde un accès en écriture au cache du proxy de dépendances au niveau du groupe et autorise implicitement les pulls via ce cache. N'accorde pas d'accès en push ou en suppression au registre de conteneurs du projet. Disponible uniquement lorsque le proxy de dépendances est activé. |
| `read_package_registry`  | Accès en lecture seule au registre de paquets du projet.                                                          |
| `write_package_registry` | Accès en écriture au registre de paquets du projet.                                                              |

## Jeton de déploiement GitLab {#gitlab-deploy-token}

Un jeton de déploiement GitLab est un type particulier de jeton de déploiement. Si vous créez un jeton de déploiement nommé `gitlab-deploy-token`, le jeton de déploiement est automatiquement exposé aux jobs CI/CD du projet en tant que variables :

- `CI_DEPLOY_USER` : nom d'utilisateur
- `CI_DEPLOY_PASSWORD` : jeton

Par exemple, pour utiliser un jeton GitLab afin de vous connecter à votre registre de conteneurs GitLab :

```shell
echo "$CI_DEPLOY_PASSWORD" | docker login $CI_REGISTRY -u $CI_DEPLOY_USER --password-stdin
```

Lorsque `gitlab-deploy-token` est défini dans un groupe, les variables CI/CD `CI_DEPLOY_USER` et `CI_DEPLOY_PASSWORD` sont disponibles uniquement pour les projets enfants directs du groupe.

## Expiration du jeton de déploiement {#deploy-token-expiration}

{{< history >}}

- Les notifications par e-mail pour l'expiration des jetons de déploiement ont été [introduites](https://gitlab.com/gitlab-org/gitlab/-/issues/512197) dans GitLab 18.3 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `project_deploy_token_expiring_notifications`. Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Les jetons de déploiement expirent à la date que vous définissez à 00:00 UTC.

GitLab vérifie chaque jour à 01:00 AM UTC les jetons de déploiement sur le point d'expirer. Les propriétaires et les mainteneurs de projet sont notifiés par e-mail 60, 30 et 7 jours avant l'expiration de ces jetons.

Ces notifications par e-mail sont envoyées une seule fois par intervalle pour les jetons de déploiement actifs (non révoqués).

### Sécurité des jetons de déploiement GitLab {#gitlab-deploy-token-security}

Les jetons de déploiement GitLab ont une longue durée de vie, ce qui les rend attractifs pour les attaquants.

Pour éviter toute fuite du jeton de déploiement, vous devez également configurer vos [runners](../../../ci/runners/_index.md) de manière sécurisée :

- Évitez d'utiliser le mode Docker `privileged` si les machines sont réutilisées.
- Évitez d'utiliser l'[exécuteur `shell`](https://docs.gitlab.com/runner/executors/shell/) lorsque les jobs s'exécutent sur la même machine.

Une configuration GitLab Runner non sécurisée augmente le risque que quelqu'un puisse voler des jetons d'autres jobs.

### API publique GitLab {#gitlab-public-api}

Les jetons de déploiement ne peuvent pas être utilisés avec l'API publique GitLab. Cependant, vous pouvez utiliser des jetons de déploiement avec certains endpoints, tels que ceux du registre de paquets. Vous pouvez identifier qu'un endpoint appartient au registre de paquets car l'URL contient la chaîne `packages/<format>`. Par exemple : `https://gitlab.example.com/api/v4/projects/24/packages/generic/my_package/0.0.1/file.txt`. Pour plus d'informations, consultez [S'authentifier auprès du registre](../../packages/package_registry/supported_functionality.md#authenticate-with-the-registry).

## Créer un jeton de déploiement {#create-a-deploy-token}

Créez un jeton de déploiement pour automatiser les tâches de déploiement pouvant s'exécuter indépendamment d'un compte utilisateur.

Prérequis :

- Pour créer un jeton de déploiement de groupe, vous devez disposer du rôle Propriétaire pour le groupe.
- Pour créer un jeton de déploiement de projet, vous devez disposer du rôle Mainteneur ou Propriétaire pour le projet.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Jetons de déploiement**.
1. Sélectionnez **Ajouter un jeton**.
1. Remplissez les champs et sélectionnez les [portées](#scope) souhaitées.
1. Sélectionnez **Créer un jeton de déploiement**.

Notez les valeurs du jeton de déploiement. Une fois que vous avez quitté ou actualisé la page, vous ne pouvez plus y accéder.

## Révoquer un jeton de déploiement {#revoke-a-deploy-token}

Révoquez un jeton lorsqu'il n'est plus nécessaire.

Prérequis :

- Pour révoquer un jeton de déploiement de groupe, vous devez disposer du rôle Propriétaire pour le groupe.
- Pour révoquer un jeton de déploiement de projet, vous devez disposer du rôle Mainteneur ou Propriétaire pour le projet.

Pour révoquer un jeton de déploiement :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Jetons de déploiement**.
1. Dans la section **Jetons de déploiement actifs**, en regard du jeton que vous souhaitez révoquer, sélectionnez **Révoquer**.

## Cloner un dépôt {#clone-a-repository}

Vous pouvez utiliser un jeton de déploiement pour cloner un dépôt.

Prérequis :

- Un jeton de déploiement avec la portée `read_repository`.

Exemple d'utilisation d'un jeton de déploiement pour cloner un dépôt :

```shell
git clone https://<username>:<deploy_token>@gitlab.example.com/tanuki/awesome_project.git
```

## Extraire des images depuis un registre de conteneurs {#pull-images-from-a-container-registry}

Vous pouvez utiliser un jeton de déploiement pour extraire des images depuis un registre de conteneurs.

Prérequis :

- Un jeton de déploiement avec la portée `read_registry`.

Exemple d'utilisation d'un jeton de déploiement pour extraire des images depuis un registre de conteneurs :

```shell
echo "$DEPLOY_TOKEN" | docker login -u <username> --password-stdin registry.example.com
docker pull $CONTAINER_TEST_IMAGE
```

## Envoyer des images vers un registre de conteneurs {#push-images-to-a-container-registry}

Vous pouvez utiliser un jeton de déploiement pour envoyer des images vers un registre de conteneurs.

Prérequis :

- Un jeton de déploiement avec les portées `read_registry` et `write_registry`.

Exemple d'utilisation d'un jeton de déploiement pour envoyer une image vers un registre de conteneurs :

```shell
echo "$DEPLOY_TOKEN" | docker login -u <username> --password-stdin registry.example.com
docker push $CONTAINER_TEST_IMAGE
```

## Extraire des paquets depuis un registre de paquets {#pull-packages-from-a-package-registry}

Vous pouvez utiliser un jeton de déploiement pour extraire des paquets depuis un registre de paquets.

Prérequis :

- Un jeton de déploiement avec la portée `read_package_registry`.

Pour le [type de paquet de votre choix](../../packages/package_registry/supported_functionality.md#authenticate-with-the-registry), suivez les instructions d'authentification pour les jetons de déploiement.

Exemple d'installation d'un paquet NuGet depuis un registre GitLab :

```shell
nuget source Add -Name GitLab -Source "https://gitlab.example.com/api/v4/projects/10/packages/nuget/index.json" -UserName <username> -Password <deploy_token>
nuget install mypkg.nupkg
```

## Publier des paquets vers un registre de paquets {#push-packages-to-a-package-registry}

Vous pouvez utiliser un jeton de déploiement pour publier des paquets vers un registre de paquets GitLab.

Prérequis :

- Un jeton de déploiement avec la portée `write_package_registry`.

Pour le [type de paquet de votre choix](../../packages/package_registry/supported_functionality.md#authenticate-with-the-registry), suivez les instructions d'authentification pour les jetons de déploiement.

Exemple de publication d'un paquet NuGet vers un registre de paquets :

```shell
nuget source Add -Name GitLab -Source "https://gitlab.example.com/api/v4/projects/10/packages/nuget/index.json" -UserName <username> -Password <deploy_token>
nuget push mypkg.nupkg -Source GitLab
```

## Extraire des images depuis le proxy de dépendances {#pull-images-from-the-dependency-proxy}

Vous pouvez utiliser un jeton de déploiement pour extraire des images depuis le proxy de dépendances. Prérequis :

- Pour le proxy de dépendances : portées `read_registry` et `write_registry`.
- Pour le registre virtuel : portées `read_virtual_registry` et `write_virtual_registry`.

Suivez les [instructions d'authentification](../../packages/dependency_proxy/_index.md) du proxy de dépendances.
