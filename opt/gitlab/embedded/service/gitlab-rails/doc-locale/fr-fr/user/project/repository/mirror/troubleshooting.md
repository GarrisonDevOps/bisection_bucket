---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Résolution des problèmes de mise en miroir de dépôt pour les projets GitLab.
title: Résolution des problèmes de mise en miroir de dépôt
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

En cas d'échec de la mise en miroir, GitLab affiche un avertissement sur la page de détails du projet. Par exemple : {{< icon name="warning-solid" >}} **Échec de la mise en miroir Pull il y a 1 heure.** Sélectionnez le texte d'avertissement pour accéder aux paramètres **Dépôts miroirs**.

À côté du dépôt concerné, GitLab affiche un badge **Erreur**. Pour afficher le message d'erreur, survolez le badge. Les messages d'erreur contiennent des détails spécifiques pour les problèmes courants, tels que les échecs d'authentification ou les branches divergentes. D'autres erreurs peuvent provenir directement des opérations Git.

## RST_STREAM reçu avec le code d'erreur 2 avec GitHub {#received-rst_stream-with-error-code-2-with-github}

Si vous recevez ce message lors de la mise en miroir vers un dépôt GitHub :

```plaintext
13:Received RST_STREAM with error code 2
```

L'un de ces problèmes est peut-être en cours :

1. Vos paramètres GitHub sont peut-être configurés pour bloquer les push qui exposent l'adresse e-mail utilisée dans les commits. Pour résoudre ce problème, vous pouvez :
   - Définir votre adresse e-mail GitHub comme publique.
   - Désactiver le paramètre [**Bloquer les pushs en ligne de commande qui exposent mon adresse e-mail**](https://github.com/settings/emails).
1. Votre dépôt dépasse la limite de taille de fichier GitHub de 100 Mo. Pour résoudre ce problème, vérifiez la limite de taille de fichier configurée sur GitHub et envisagez d'utiliser [Git Large File Storage (LFS)](https://git-lfs.com/) pour gérer les fichiers volumineux.

## Délai dépassé {#deadline-exceeded}

Lorsque vous mettez à niveau GitLab, un changement dans la représentation des noms d'utilisateur implique que vous devez mettre à jour votre nom d'utilisateur et votre mot de passe de mise en miroir pour vous assurer que les caractères `%40` sont remplacés par `@`.

## Connexion bloquée : le serveur n'autorise que l'authentification par clé publique {#connection-blocked-server-only-allows-public-key-authentication}

La connexion entre GitLab et le dépôt distant est bloquée. Même si une [vérification TCP](../../../../administration/raketasks/maintenance.md#check-tcp-connectivity-to-a-remote-site) réussit, vous devez vérifier tous les composants réseau sur le chemin entre GitLab et le serveur distant pour détecter tout blocage.

Cette erreur peut se produire lorsqu'un pare-feu effectue une `Deep SSH Inspection` sur les paquets sortants.

## Impossible de lire le nom d'utilisateur : invites du terminal désactivées {#could-not-read-username-terminal-prompts-disabled}

Si vous recevez cette erreur après avoir créé un nouveau projet à l'aide de [GitLab CI/CD pour les dépôts externes](../../../../ci/ci_cd_for_external_repos/_index.md) :

- Dans Bitbucket Cloud :

  ```plaintext
  "2:fetch remote: "fatal: could not read Username for 'https://bitbucket.org':
  terminal prompts disabled\n": exit status 128."
  ```

- Dans Bitbucket Server (auto-hébergé) :

  ```plaintext
  "2:fetch remote: "fatal: could not read Username for 'https://lab.example.com':
  terminal prompts disabled\n": exit status 128.
  ```

Vérifiez si le propriétaire du dépôt est spécifié dans l'URL de votre dépôt miroir :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Dépôts miroirs**.
1. Si aucun propriétaire de dépôt n'est spécifié, supprimez l'URL et ajoutez-la à nouveau dans ce format, en remplaçant `OWNER`, `ACCOUNTNAME`, `PATH_TO_REPO` et `REPONAME` par vos valeurs :

   - Dans Bitbucket Cloud :

     ```plaintext
     https://OWNER@bitbucket.org/ACCOUNTNAME/REPONAME.git
     ```

   - Dans Bitbucket Server (auto-hébergé) :

     ```plaintext
     https://OWNER@lab.example.com/PATH_TO_REPO/REPONAME.git
     ```

Lors de la connexion au dépôt Bitbucket Cloud ou auto-hébergé pour la mise en miroir, le propriétaire du dépôt est obligatoire dans la chaîne.

## Miroir push : `LFS objects are missing` {#push-mirror-lfs-objects-are-missing}

Vous pourriez obtenir une erreur indiquant :

```plaintext
GitLab: GitLab: LFS objects are missing. Ensure LFS is properly set up or try a manual "git lfs push --all".
```

Ce problème se produit lorsque vous utilisez une URL de dépôt SSH pour la mise en miroir push. La mise en miroir push pour transférer des fichiers LFS via SSH n'est pas prise en charge.

La solution de contournement consiste à utiliser une URL de dépôt HTTPS à la place de SSH pour votre miroir push.

Le [ticket 249587](https://gitlab.com/gitlab-org/gitlab/-/issues/249587) existe pour corriger ce problème.

## Erreur : `Committer is not a member of team` {#error-committer-is-not-a-member-of-team}

Vous pourriez obtenir une erreur indiquant :

```plaintext
remote: GitLab: Committer 'noreply@example.com' is not a member of team
```

Ce problème se produit lorsque le projet source signe les commits créés dans l'interface GitLab et que le projet cible a la **Vérifier si l'auteur de la validation est un utilisateur de GitLab** [règle push](../push_rules.md#verify-users) activée. Les commits signés par GitLab ont une adresse e-mail d'instance comme auteur du commit, et cette adresse n'appartient pas à un utilisateur GitLab.

GitLab 19.3 et les versions ultérieures résolvent ce problème : les règles push ne vérifient plus l'adresse e-mail de l'auteur du commit pour les [commits signés par GitLab](../push_rules.md#commits-signed-by-gitlab). Pour les versions antérieures, la solution de contournement consiste à désactiver la règle push sur le projet cible.

## Des fichiers LFS manquent dans le miroir pull {#pull-mirror-is-missing-lfs-files}

Dans certains cas, la mise en miroir pull ne transfère pas les fichiers LFS. Ce problème se produit lorsque vous utilisez une URL de dépôt SSH.

La solution de contournement consiste à utiliser une URL de dépôt HTTPS à la place.

## La mise en miroir pull ne déclenche pas de pipelines {#pull-mirroring-is-not-triggering-pipelines}

Les pipelines peuvent ne pas s'exécuter pour plusieurs raisons :

- L'option [Déclencher des pipelines pour les mises à jour du miroir](pull.md#trigger-pipelines-for-mirror-updates) n'est peut-être pas activée. Ce paramètre ne peut être activé que lors de la [configuration initiale de la mise en miroir pull](pull.md#configure-pull-mirroring). Le statut [n'est pas affiché](https://gitlab.com/gitlab-org/gitlab/-/issues/346630) lors de la vérification ultérieure du projet.

  Lorsque la mise en miroir est configurée à l'aide de [CI/CD pour les dépôts externes](../../../../ci/ci_cd_for_external_repos/_index.md), ce paramètre est activé par défaut. Si la mise en miroir du dépôt est reconfigurée manuellement, le déclenchement des pipelines est désactivé par défaut, ce qui pourrait expliquer l'arrêt des pipelines.
- La configuration [`rules`](../../../../ci/yaml/_index.md#rules) empêche l'ajout de jobs au pipeline.
- Les pipelines sont déclenchés à l'aide de [le compte qui a configuré le miroir pull](https://gitlab.com/gitlab-org/gitlab/-/issues/13697). Si le compte n'est plus valide, les pipelines ne s'exécutent pas.
- La [protection de branche](../branches/protected.md#cicd-on-protected-branches) peut empêcher le compte qui a configuré la mise en miroir d'exécuter des pipelines.

## `The repository is being updated`, mais n'échoue ni ne réussit visiblement {#the-repository-is-being-updated-but-neither-fails-nor-succeeds-visibly}

Dans de rares cas, les emplacements de mise en miroir sur Redis peuvent être épuisés, peut-être parce que les workers Sidekiq sont supprimés en raison d'événements de mémoire insuffisante (OoM). Lorsque cela se produit, les jobs de mise en miroir démarrent et se terminent rapidement, mais ils n'échouent ni ne réussissent. Ils ne laissent pas non plus de journal clair. Pour vérifier ce problème :

1. Accédez à la [console Rails](../../../../administration/operations/rails_console.md) et vérifiez la capacité de mise en miroir Redis :

   ```ruby
   current = Gitlab::Redis::SharedState.with { |redis| redis.scard('MIRROR_PULL_CAPACITY') }.to_i
   maximum = Gitlab::CurrentSettings.mirror_max_capacity
   available = maximum - current
   ```

1. Si la capacité de mise en miroir est `0` ou très faible, vous pouvez vider tous les jobs bloqués avec :

   ```ruby
   Gitlab::Redis::SharedState.with { |redis| redis.smembers('MIRROR_PULL_CAPACITY') }.each do |pid|
     Gitlab::Redis::SharedState.with { |redis| redis.srem('MIRROR_PULL_CAPACITY', pid) }
   end
   ```

1. Après avoir exécuté la commande, la [page des jobs en arrière-plan](../../../../administration/admin_area.md#background-jobs) devrait afficher de nouveaux jobs de mise en miroir planifiés, notamment lorsqu'ils sont [déclenchés manuellement](_index.md#update-a-mirror).

## URL non valide {#invalid-url}

Si vous recevez cette erreur lors de la configuration de la mise en miroir via [SSH](_index.md#ssh-authentication), assurez-vous que l'URL est dans un format valide.

La mise en miroir ne prend pas en charge les URL de clonage de type SCP sous la forme `git@gitlab.com:gitlab-org/gitlab.git`, avec l'hôte et le chemin du projet séparés par `:`. Elle nécessite une [URL standard](https://git-scm.com/docs/git-clone#_git_urls) qui inclut le protocole `ssh://`, comme `ssh://git@gitlab.com/gitlab-org/gitlab.git`.

## Échec de la vérification de la clé d'hôte {#host-key-verification-failed}

Cette erreur est renvoyée lorsque la clé SSH publique de l'hôte cible change. Les clés SSH publiques changent rarement. Si la vérification de la clé d'hôte échoue, mais que vous pensez que la clé est toujours valide, vous devez supprimer le miroir du dépôt et le recréer. Pour plus d'informations, consultez [créer un miroir de dépôt](_index.md#create-a-repository-mirror).

## Mise en miroir du dépôt désactivée car l'utilisateur miroir a été supprimé {#repository-mirroring-disabled-because-mirror-user-was-deleted}

Vous pourriez recevoir une notification par e-mail similaire à :

```plaintext
Repository mirroring on <project_path> was disabled because the mirror user <username> was deleted.

To re-enable mirroring, update your repository mirroring settings.
```

Ce problème se produit parce que chaque miroir est lié à l'utilisateur qui l'a configuré. Lorsque le compte de cet utilisateur est supprimé, GitLab désactive automatiquement le miroir. Le même comportement s'applique lorsqu'un jeton d'accès de groupe ou un jeton d'accès au projet utilisé pour créer le miroir est révoqué, car l'utilisateur bot associé est également supprimé.

Vous ne pouvez pas réaffecter un miroir à un autre utilisateur. Pour résoudre ce problème, configurez à nouveau le miroir avec un autre utilisateur.

Pour plus d'informations, consultez le [ticket 488449](https://gitlab.com/gitlab-org/gitlab/-/work_items/488449).

## Transférer les utilisateurs et les jetons de miroir vers un compte de service unique {#transfer-mirror-users-and-tokens-to-a-single-service-account}

Cette opération nécessite l'accès à la [console Rails GitLab](../../../../administration/operations/rails_console.md#starting-a-rails-console-session).

Cas d'utilisation : si plusieurs utilisateurs utilisent leurs propres identifiants GitHub pour configurer la mise en miroir de dépôt, la mise en miroir est interrompue lorsque ces personnes quittent l'entreprise. Utilisez ce script pour migrer les utilisateurs et les jetons de mise en miroir disparates vers un compte de service unique :

> [!warning]
> Les commandes qui modifient des données peuvent causer des dommages si elles ne sont pas exécutées correctement ou dans les bonnes conditions. Exécutez toujours les commandes dans un environnement de test en premier et disposez d'une instance de sauvegarde prête à être restaurée.

```ruby
svc_user = User.find_by(username: 'ourServiceUser')
token = 'githubAccessToken'

Project.where(mirror: true).each do |project|
  import_url = project.unsafe_import_url

  # The expected url output is https://token@project/path.git
  repo_url = if import_url.include?('@')
               # Case 1: The url is something like https://23423432@project/path.git
               import_url.split('@').last
             elsif import_url.include?('//')
               # Case 2: The url is something like https://project/path.git
               import_url.split('//').last
             end

  next unless repo_url

  final_url = "https://#{token}@#{repo_url}"

  project.mirror_user = svc_user
  project.import_url = final_url
  project.username_only_import_url = final_url
  project.save
end
```

## `The requested URL returned error: 301` {#the-requested-url-returned-error-301}

Lors de la mise en miroir avec les protocoles `http://` ou `https://`, assurez-vous de spécifier l'URL exacte du dépôt : `https://gitlab.example.com/group/project.git`

Les redirections HTTP ne sont pas suivies et l'omission de `.git` peut entraîner une erreur 301 :

```plaintext
13:fetch remote: "fatal: unable to access 'https://gitlab.com/group/project': The requested URL returned error: 301\n": exit status 128.
```

## Échec du miroir push de l'instance GitLab vers le nœud secondaire Geo {#push-mirror-from-gitlab-instance-to-geo-secondary-fails}

La mise en miroir push d'un dépôt GitLab via les protocoles HTTP ou HTTPS échoue lorsque la destination est un nœud secondaire Geo, en raison du proxying de la requête push vers le nœud primaire Geo, et l'erreur suivante s'affiche :

```plaintext
13:get remote references: create git ls-remote: exit status 128, stderr: "fatal: unable to access 'https://gitlab.example.com/group/destination.git/': The requested URL returned error: 302".
```

Cela se produit lorsqu'une URL unifiée Geo est configurée et que le nom d'hôte cible est résolu vers l'adresse IP du nœud secondaire.

L'erreur peut être évitée en :

- Configurant le miroir push pour utiliser le protocole SSH. Cependant, le dépôt ne doit contenir aucun objet LFS, qui sont toujours transférés via HTTP ou HTTPS et sont toujours redirigés.
- Utilisant un proxy inverse pour diriger toutes les requêtes de l'instance source vers le nœud Geo primaire.
- Ajoutant une entrée de fichier `hosts` local sur la source pour forcer la résolution du nom d'hôte cible vers l'adresse IP du nœud primaire Geo.
- Configurant un miroir pull sur la cible à la place.

## Échec de la mise à jour du miroir pull ou push : `The project is not mirrored` {#pull-or-push-mirror-fails-to-update-the-project-is-not-mirrored}

Les miroirs pull et push ne parviennent pas à se mettre à jour lorsque le [mode silencieux GitLab](../../../../administration/silent_mode/_index.md) est activé. Dans ce cas, l'option permettant d'autoriser la mise en miroir dans l'interface est désactivée.

Un administrateur peut vérifier que le mode silencieux GitLab est désactivé.

Lorsque la mise en miroir échoue en raison du mode silencieux, voici les étapes de débogage :

- [Le déclenchement du miroir via l'API](pull.md#trigger-pipelines-for-mirror-updates) affiche : `The project is not mirrored`.
- Si le miroir pull ou push était déjà configuré mais qu'il n'y a plus de mises à jour sur le dépôt miroir, confirmez que les [détails et le statut du miroir pull et push du projet](../../../../api/project_pull_mirroring.md#retrieve-project-pull-mirror-details) ne sont pas récents comme indiqué ci-dessous. Cela indique que la mise en miroir a été suspendue et que la désactivation du mode silencieux GitLab la redémarre automatiquement.

Par exemple, si le mode silencieux est ce qui bloque vos imports, la sortie est similaire à ce qui suit :

```json
"id": 1,
"update_status": "finished",
"url": "https://test.git"
"last_error": null,
"last_update_at": null,
"last_update_started_at": "2023-12-12T00:01:02.222Z",
"last_successful_update_at": null
```

## Échec de la mise en miroir initiale : `Unable to pull mirror repo: Unable to get pack index` {#initial-mirroring-fails-unable-to-pull-mirror-repo-unable-to-get-pack-index}

Vous pourriez obtenir une erreur similaire à ce qui suit :

```plaintext
13:fetch remote: "error: Unable to open local file /var/opt/gitlab/git-data/repositories/+gitaly/tmp/quarantine-[OMITTED].idx.temp.temp\nerror: Unable to get pack index https://git.example.org/ebtables/objects/pack/pack-[OMITTED].idx\nerror: Unable to find fcde2b2edba56bf408601fb721fe9b5c338d10ee under https://git.example.org/ebtables
Cannot obtain needed object fcde2b2edba56bf408601fb721fe9b5c338d10ee
while processing commit 2c26b46b68ffc68ff99b453c1d30413413422d70.
error: fetch failed.\n": exit status 128.
```

Ce problème se produit parce que Gitaly ne prend pas en charge la mise en miroir ou l'importation de dépôts via le protocole HTTP « dumb ».

Pour déterminer si un serveur est « smart » ou « dumb », utilisez cURL pour démarrer une découverte de références pour le service `git-upload-pack` et émuler un client Git « smart » :

```shell
$GIT_URL="https://git.example.org/project"
curl --silent --dump-header - "$GIT_URL/info/refs?service=git-upload-pack"\
  -o /dev/null | grep -Ei "$content-type:"
```

- Un [serveur « smart »](https://www.git-scm.com/docs/http-protocol#_smart_server_response) renvoie `application/x-git-upload-pack-advertisement` dans l'en-tête de réponse `Content-Type`.
- Un serveur « dumb » renvoie `text/plain` dans l'en-tête de réponse `Content-Type`.

Pour plus d'informations, consultez la [documentation Git sur la découverte des références](https://www.git-scm.com/docs/http-protocol#_discovering_references).

Pour résoudre ce problème, vous pouvez effectuer l'une des opérations suivantes :

- Migrer le dépôt source vers un serveur « smart ».
- Mettre en miroir le dépôt à l'aide du [protocole SSH](_index.md#ssh-authentication) (nécessite une authentification).

## Échec de la mise en miroir pull avec `Could not update main` {#pull-mirroring-fails-with-could-not-update-main}

Vous pourriez obtenir une erreur similaire à :

- `9:Could not update main. Please refresh and try again.`

Cela peut se produire lors de la mise à jour initiale du miroir pull si le dépôt de destination n'est pas complètement vide.

Par exemple, le dépôt de destination peut déjà contenir :

- Un commit README initial.
- Une licence ou un fichier `.gitignore`.
- Des branches ou des tags existants.

Pour résoudre ce problème :

1. Recréez le dépôt de destination en tant que dépôt vide.
1. Assurez-vous que le dépôt utilise le même format d'objet que le dépôt source.
1. N'initialisez pas le dépôt avec un fichier README, une licence ou un fichier `.gitignore`.
1. Configurez à nouveau la mise en miroir pull et exécutez **Mettre à jour maintenant**.

Pour contournement, si vous devez conserver le dépôt de destination existant, activez **Écraser les branches divergentes** et assurez-vous que l'utilisateur de mise en miroir a la permission d'écraser la branche cible.

## Erreur : `mismatched algorithms` {#error-mismatched-algorithms}

Vous pourriez obtenir une erreur similaire à :

```plaintext
13:fetch remote: "fatal: mismatched algorithms: client sha1; server sha256": exit status 128.
```

Cette erreur se produit lorsque les dépôts source et de destination utilisent des formats d'objet différents et que la mise en miroir pull n'est pas prise en charge entre des dépôts utilisant des formats d'objet différents.

Par exemple :

- Le dépôt source utilise SHA-1.
- Le dépôt de destination utilise SHA-256 ou vice versa.

Pour résoudre ce problème, recréez le dépôt de destination avec le même format d'objet que le dépôt source, puis reconfigurez la mise en miroir.

## Erreur : `File directory conflict` {#error-file-directory-conflict}

Vous pourriez obtenir une erreur similaire à ce qui suit :

```plaintext
13:preparing reference update: file directory conflict
```

Cette erreur se produit lorsqu'un conflit de nom de tag ou de branche existe entre les dépôts source et miroir. Par exemple :

- Un tag ou une branche nommé `x/y` existe dans le dépôt miroir.
- Un tag ou une branche nommé `x` existe dans le dépôt source.

Pour résoudre ce problème, supprimez le tag ou la branche en conflit. Si vous ne pouvez pas identifier le tag ou la branche en conflit, supprimez tous les tags de votre dépôt miroir. Une autre option consiste à [écraser les branches divergentes](pull.md#overwrite-diverged-branches).

> [!note]
> La suppression des tags peut être destructrice pour tout travail effectué dans le dépôt miroir.

Pour supprimer tous les tags du dépôt miroir :

1. Sur une copie locale de votre dépôt miroir, exécutez :

   ```shell
   git tag -l | xargs -n 1 git push --delete origin
   ```

1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Dépôts miroirs**.
1. Sélectionnez **Mettre à jour maintenant** ({{< icon name="retry" >}}).

## Mise en miroir push bloquée avec des fichiers LFS volumineux {#push-mirroring-stuck-with-large-lfs-files}

Vous pourriez rencontrer des problèmes de délai d'attente lors de la mise en miroir push d'un projet contenant des objets LFS volumineux. Ce problème se produit lorsque les opérations Git LFS dépassent le délai d'activité par défaut. Cette erreur apparaît dans les journaux de mise en miroir :

```plaintext
push to mirror: git push: exit status 1, stderr: "remote: GitLab: LFS objects are missing. Ensure LFS is properly set up or try a manual \"git lfs push --all\""
```

Pour résoudre ce problème, augmentez la valeur du délai d'activité LFS avant de configurer le miroir :

```shell
git config lfs.activitytimeout 240
```

Cette commande définit le délai d'attente sur `240` secondes. Vous pouvez ajuster cette valeur en fonction de la taille de vos fichiers et des conditions réseau.
