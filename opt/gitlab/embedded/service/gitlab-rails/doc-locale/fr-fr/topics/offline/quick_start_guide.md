---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Installez, configurez et utilisez une instance GitLab Self-Managed dans un environnement sans accès à Internet."
title: Installer une instance GitLab Self-Managed hors ligne
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Il s'agit d'un guide étape par étape qui vous aide à installer, configurer et utiliser une instance GitLab Self-Managed entièrement hors ligne.

## Installation {#installation}

> [!note]
> Ce guide suppose que le serveur exécute Ubuntu 20.04 en utilisant la [méthode d'installation par package Linux](../../install/package/_index.md) et qu'il fait tourner GitLab Enterprise Edition. Les instructions peuvent varier pour d'autres serveurs. Ce guide suppose également que l'hôte du serveur se résout en `my-host.internal`, que vous devez remplacer par le FQDN de votre serveur, et que vous avez accès à un autre serveur disposant d'un accès à Internet pour télécharger les fichiers de package requis.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une présentation vidéo de ce processus, consultez [Installation GitLab hors ligne : téléchargement et installation](https://www.youtube.com/watch?v=TJaq4ua2Prw).

### Télécharger le package GitLab {#download-the-gitlab-package}

Vous devez [télécharger le package GitLab](../../update/package/_index.md#upgrade-with-a-downloaded-package) et les dépendances pertinentes en utilisant un serveur du même type de système d'exploitation disposant d'un accès à Internet.

Si votre environnement hors ligne ne dispose d'aucun accès au réseau local, vous devez transporter manuellement le package requis via un support physique, tel qu'une clé USB.

Sous Ubuntu, cette opération peut être effectuée sur un serveur disposant d'un accès à Internet à l'aide des commandes suivantes :

```shell
# Download the bash script to prepare the repository
curl --silent "https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.deb.sh" | sudo bash

# Download the gitlab-ee package and dependencies to /var/cache/apt/archives
sudo apt-get install --download-only gitlab-ee

# Copy the contents of the apt download folder to a mounted media device
sudo cp /var/cache/apt/archives/*.deb /path/to/mount
```

### Installer le package GitLab {#install-the-gitlab-package}

Prérequis :

- Avant d'installer le package GitLab dans votre environnement hors ligne, assurez-vous d'avoir installé toutes les dépendances requises au préalable.

Si vous utilisez Ubuntu, vous pouvez installer les packages de dépendances `.deb` que vous avez copiés à l'aide de `dpkg`. N'installez pas encore le package GitLab.

```shell
# Go to the physical media device
sudo cd /path/to/mount

# Install the dependency packages
sudo dpkg -i <package_name>.deb
```

[Utilisez les commandes appropriées à votre système d'exploitation pour installer le package](../../update/package/_index.md#upgrade-with-a-downloaded-package), mais veillez à spécifier une URL `http` pour l'étape d'installation de `EXTERNAL_URL`. Une fois installé, vous pouvez configurer manuellement le SSL vous-même.

Vous devez configurer un domaine pour la résolution IP plutôt que de lier l'adresse IP du serveur. Un domaine constitue une cible stable pour le Common Name (CN) du certificat et simplifie la résolution à long terme.

L'exemple suivant pour Ubuntu spécifie `EXTERNAL_URL` en utilisant HTTP et installe le package GitLab :

```shell
sudo EXTERNAL_URL="http://my-host.internal" dpkg -i <gitlab_package_name>.deb
```

## Activation du SSL {#enabling-ssl}

Suivez ces étapes pour activer le SSL sur votre nouvelle instance. Ces étapes reflètent celles relatives à la [configuration manuelle du SSL dans la configuration NGINX](https://docs.gitlab.com/omnibus/settings/ssl/#configure-https-manually) :

1. Apportez les modifications suivantes à `/etc/gitlab/gitlab.rb` :

   ```ruby
   # Update external_url from "http" to "https"
   external_url "https://my-host.internal"

   # Set Let's Encrypt to false
   letsencrypt['enable'] = false
   ```

1. Créez les répertoires suivants avec les permissions appropriées pour générer des certificats auto-signés :

   ```shell
   sudo mkdir -p /etc/gitlab/ssl
   sudo chmod 755 /etc/gitlab/ssl
   sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/gitlab/ssl/my-host.internal.key -out /etc/gitlab/ssl/my-host.internal.crt
   ```

1. Reconfigurez votre instance pour appliquer les modifications :

   ```shell
   sudo gitlab-ctl reconfigure
   ```

## Activation du registre de conteneurs GitLab {#enabling-the-gitlab-container-registry}

Suivez ces étapes pour activer le registre de conteneurs. Ces étapes reflètent celles relatives à la [configuration du registre de conteneurs sous un domaine existant](../../administration/packages/container_registry.md#configure-container-registry-under-an-existing-gitlab-domain) :

1. Apportez les modifications suivantes à `/etc/gitlab/gitlab.rb` :

   ```ruby
   # Change external_registry_url to match external_url, but append the port 4567
   external_url "https://gitlab.example.com"
   registry_external_url "https://gitlab.example.com:4567"
   ```

1. Reconfigurez votre instance pour appliquer les modifications :

   ```shell
   sudo gitlab-ctl reconfigure
   ```

## Autoriser le daemon Docker à faire confiance au registre et à GitLab Runner {#allow-the-docker-daemon-to-trust-the-registry-and-gitlab-runner}

Fournissez vos certificats au daemon Docker en [suivant les étapes d'utilisation des certificats approuvés avec votre registre](../../administration/packages/container_registry.md#configure-self-signed-certificates) :

```shell
sudo mkdir -p /etc/docker/certs.d/my-host.internal:5000

sudo cp /etc/gitlab/ssl/my-host.internal.crt /etc/docker/certs.d/my-host.internal:5000/ca.crt
```

Fournissez vos certificats à votre GitLab Runner (qui sera installé ensuite) en [suivant les étapes d'utilisation des certificats approuvés avec votre runner](https://docs.gitlab.com/runner/install/docker/#installing-trusted-ssl-server-certificates) :

```shell
sudo mkdir -p /etc/gitlab-runner/certs

sudo cp /etc/gitlab/ssl/my-host.internal.crt /etc/gitlab-runner/certs/ca.crt
```

## Activation de GitLab Runner {#enabling-gitlab-runner}

[En suivant un processus similaire aux étapes d'installation de GitLab Runner en tant que service Docker](https://docs.gitlab.com/runner/install/docker/#install-the-docker-image-and-start-the-container), vous devez d'abord enregistrer votre runner :

```shell
$ sudo docker run --rm -it -v /etc/gitlab-runner:/etc/gitlab-runner gitlab/gitlab-runner register
Updating CA certificates...
Runtime platform                                    arch=amd64 os=linux pid=7 revision=1b659122 version=12.8.0
Running in system-mode.

Enter the GitLab instance URL (for example, https://gitlab.com/):
https://my-host.internal
Enter the registration token:
XXXXXXXXXXX
Enter a description for the runner:
[eb18856e13c0]:
Enter tags for the runner (comma-separated):
Enter optional maintenance note for the runner:

Registering runner... succeeded                     runner=FSMwkvLZ
Please enter the executor: custom, docker, virtualbox, kubernetes, docker+machine, docker-ssh+machine, docker-ssh, parallels, shell, ssh:
docker
Please enter the default Docker image (for example, ruby:2.6):
ruby:2.6
Runner registered successfully. Feel free to start it, but if it's running already the config should be automatically reloaded!
```

Vous devez ensuite ajouter des configurations supplémentaires à votre runner.

Apportez les modifications suivantes à `/etc/gitlab-runner/config.toml` :

- Ajoutez le socket Docker aux volumes `volumes = ["/var/run/docker.sock:/var/run/docker.sock", "/cache"]`
- Ajoutez `pull_policy = "if-not-present"` à la configuration de l'exécuteur

Vous pouvez maintenant démarrer votre runner :

```shell
sudo docker run -d --restart always --name gitlab-runner -v /etc/gitlab-runner:/etc/gitlab-runner -v /var/run/docker.sock:/var/run/docker.sock gitlab/gitlab-runner:latest
90646b6587127906a4ee3f2e51454c6e1f10f26fc7a0b03d9928d8d0d5897b64
```

### Authentification du registre auprès du système d'exploitation hôte {#authenticating-the-registry-against-the-host-os}

Comme indiqué dans la [documentation sur l'authentification du registre Docker](https://distribution.github.io/distribution/about/insecure/#docker-still-complains-about-the-certificate-when-using-authentication), certaines versions de Docker requièrent de faire confiance à la chaîne de certificats au niveau du système d'exploitation.

Dans le cas d'Ubuntu, cela implique l'utilisation de `update-ca-certificates` :

```shell
sudo cp /etc/docker/certs.d/my-host.internal\:5000/ca.crt /usr/local/share/ca-certificates/my-host.internal.crt

sudo update-ca-certificates
```

Si tout se passe bien, voici ce que vous devriez voir :

```plaintext
1 added, 0 removed; done.
Running hooks in /etc/ca-certificates/update.d...
done.
```

### Désactiver la vérification de version et le ping de service {#disable-version-check-and-service-ping}

La vérification de version et le ping de service améliorent l'expérience utilisateur de GitLab et garantissent que les utilisateurs disposent des instances GitLab les plus récentes. Ces deux services peuvent être désactivés pour les environnements hors ligne afin qu'ils ne tentent pas de contacter les services GitLab et n'échouent pas.

Pour plus d'informations, consultez [Activer ou désactiver le ping de service](../../administration/settings/usage_statistics.md#enable-or-disable-service-ping).

### Désactiver la gestion des versions du runner {#disable-runner-version-management}

La gestion des versions du runner récupère les dernières versions du runner depuis GitLab pour [déterminer quels runners de votre environnement sont obsolètes](../../ci/runners/runners_scope.md#determine-which-runners-need-to-be-upgraded). Vous devez [désactiver la gestion des versions du runner](../../administration/settings/continuous_integration.md#control-runner-version-management) pour les environnements hors ligne.

### Configurer NTP {#configure-ntp}

Gitaly Cluster (Praefect) suppose que `pool.ntp.org` est accessible. Si `pool.ntp.org` n'est pas accessible, [personnalisez le paramètre du serveur de temps](../../administration/gitaly/praefect/configure.md#customize-time-server-setting) sur les serveurs Gitaly et Praefect afin qu'ils puissent utiliser un serveur NTP accessible.

Sur les instances hors ligne, la [tâche Rake de vérification GitLab Geo](../../administration/geo/replication/troubleshooting/common.md#can-geo-detect-the-current-site-correctly) échoue toujours car elle utilise `pool.ntp.org`. Cette erreur peut être ignorée, mais vous pouvez [en savoir plus sur la façon de la contourner](../../administration/geo/replication/troubleshooting/common.md#message-machine-clock-is-synchronized--exception).

## Activation de la base de données de métadonnées de packages {#enabling-the-package-metadata-database}

[L'analyse continue des vulnérabilités](../../user/application_security/continuous_vulnerability_scanning/_index.md) et [l'analyse des licences des fichiers CycloneDX](../../user/compliance/license_scanning_of_cyclonedx_files/_index.md) lisent la base de données de métadonnées de packages. Une instance hors ligne ne peut pas la télécharger. Vous devez donc la télécharger sur une machine disposant d'un accès à Internet, puis la copier sur l'instance.

- Pour connaître le contenu de la base de données et la version du format de données que lit votre version de GitLab, consultez [Base de données de métadonnées de packages](../../user/application_security/detect/package-metadata-database.md).
- Pour les procédures de téléchargement et de copie, consultez [Base de données de métadonnées de packages pour les instances hors ligne](package-metadata-database.md).
