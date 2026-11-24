---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Résolution des problèmes liés aux migrations de projets par export de fichiers
description: "Résolution des problèmes liés aux migrations de projets par export de fichiers. Couvre les erreurs courantes, les problèmes de performance et les solutions."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si vous rencontrez des problèmes avec [la migration de projets par export de fichiers](import_export.md), consultez les solutions possibles ci-dessous.

## Commandes de résolution des problèmes {#troubleshooting-commands}

Utilisez la [console Rails](../../../administration/operations/rails_console.md) pour trouver des informations sur le statut de l'import et les journaux supplémentaires en utilisant le JID :

```ruby
Project.find_by_full_path('group/project').import_state.slice(:jid, :status, :last_error)
> {"jid"=>"414dec93f941a593ea1a6894", "status"=>"finished", "last_error"=>nil}
```

```shell
# Logs
grep JID /var/log/gitlab/sidekiq/current
grep "Import/Export error" /var/log/gitlab/sidekiq/current
grep "Import/Export backtrace" /var/log/gitlab/sidekiq/current
tail /var/log/gitlab/gitlab-rails/importer.log
```

## Échec de l'import d'un projet en raison d'une incompatibilité {#project-fails-to-import-due-to-mismatch}

Si l'[activation des runners d'instance](../../../ci/runners/runners_scope.md#enable-instance-runners-for-a-project) ne correspond pas entre le projet exporté et le projet importé, l'import du projet échoue. Consultez le [ticket 276930](https://gitlab.com/gitlab-org/gitlab/-/issues/276930), puis effectuez l'une des actions suivantes :

- Assurez-vous que les runners d'instance sont activés dans les projets source et de destination.
- Désactivez les runners d'instance sur le groupe parent lors de l'import du projet.

## Utilisateurs manquants dans le projet importé {#users-missing-from-imported-project}

Si les utilisateurs ne sont pas importés avec les projets importés, consultez les exigences relatives à la [préservation des contributions des utilisateurs](import_export.md#preserving-user-contributions).

Une raison fréquente des utilisateurs manquants est que le [paramètre d'e-mail public](../../profile/_index.md#set-your-public-email) n'est pas configuré pour les utilisateurs. Pour résoudre ce problème, demandez aux utilisateurs de configurer ce paramètre via l'interface GitLab.

Si le nombre d'utilisateurs est trop important pour qu'une configuration manuelle soit faisable, vous pouvez définir tous les profils utilisateur pour utiliser une adresse e-mail publique à l'aide de la [console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session) :

```ruby
User.where("public_email IS NULL OR public_email = '' ").find_each do |u|
  next if u.bot?

  puts "Setting #{u.username}'s currently empty public email to #{u.email}…"
  u.public_email = u.email
  u.save!
end
```

## Solutions de contournement pour l'import de grands dépôts {#import-workarounds-for-large-repositories}

Les [limitations de taille maximale d'import](import_export.md#import-a-project-and-its-data) peuvent empêcher un import de se terminer avec succès. Si la modification des limites d'import n'est pas possible, vous pouvez essayer l'une des solutions de contournement répertoriées ici.

### Solution de contournement option 1 {#workaround-option-1}

Le workflow local suivant peut être utilisé pour réduire temporairement la taille du dépôt en vue d'une nouvelle tentative d'import :

1. Créez un répertoire de travail temporaire à partir de l'export :

   ```shell
   EXPORT=<filename-without-extension>

   mkdir "$EXPORT"
   tar -xf "$EXPORT".tar.gz --directory="$EXPORT"/
   cd "$EXPORT"/
   git clone project.bundle

   # Prevent interference with recreating an importable file later
   mv project.bundle ../"$EXPORT"-original.bundle
   mv ../"$EXPORT".tar.gz ../"$EXPORT"-original.tar.gz

   git switch --create smaller-tmp-main
   ```

1. Pour réduire la taille du dépôt, travaillez sur la branche `smaller-tmp-main` : [identifiez et supprimez les fichiers volumineux](../repository/repository_size.md#methods-to-reduce-repository-size) ou effectuez un [rebase interactif et fixup](../../../topics/git/git_rebase.md#interactive-rebase) pour réduire le nombre de commits.

   ```shell
   # Reduce the .git/objects/pack/ file size
   cd project
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive

   # Prepare recreating an importable file
   git bundle create ../project.bundle <default-branch-name>
   cd ..
   mv project/ ../"$EXPORT"-project
   cd ..

   # Recreate an importable file
   tar -czf "$EXPORT"-smaller.tar.gz --directory="$EXPORT"/ .
   ```

1. Importez ce nouveau fichier plus petit dans GitLab.
1. Dans un clone complet du dépôt d'origine, utilisez `git remote set-url origin <new-url> && git push --force --all` pour finaliser l'import.
1. Mettez à jour les [règles de protection des branches](../repository/branches/protected.md) du dépôt importé ainsi que sa [branche par défaut](../repository/branches/default.md), supprimez la branche temporaire `smaller-tmp-main` et les données locales temporaires.

### Solution de contournement option 2 {#workaround-option-2}

> [!note]
> Cette solution de contournement ne prend pas en compte les objets LFS.

Plutôt que de tenter de pousser toutes les modifications en une seule fois, cette solution de contournement :

- Sépare l'import du projet de l'import du dépôt Git
- Pousse le dépôt vers GitLab de manière incrémentielle

1. Effectuez un clone local du dépôt à migrer. Dans une étape ultérieure, vous poussez ce clone en dehors de l'export du projet.
1. Téléchargez l'export et supprimez le fichier `project.bundle` (qui contient le dépôt Git) :

   ```shell
   tar -czvf new_export.tar.gz --exclude='project.bundle' @old_export.tar.gz
   ```

1. Importez l'export sans dépôt Git. Le système vous demande de confirmer que vous souhaitez importer sans dépôt.
1. Enregistrez ce script bash dans un fichier et exécutez-le après avoir ajouté l'origine appropriée.

   ```shell
   #!/bin/sh

   # ASSUMPTIONS:
   # - The GitLab location is "origin"
   # - The default branch is "main"
   # - This will attempt to push in chunks of 500 MB (dividing the total size by 500 MB).
   #   Decrease this size to push in smaller chunks if you still receive timeouts.

   git gc
   SIZE=$(git count-objects -v 2> /dev/null | grep size-pack | awk '{print $2}')

   # Be conservative and try to push 2 GB at a time
   # (given this assumes each commit is the same size - which is wrong)
   BATCHES=$(($SIZE / 500000))
   TOTAL_COMMITS=$(git rev-list --count HEAD)
   if (( BATCHES > TOTAL_COMMITS )); then
       BATCHES=$TOTAL_COMMITS
   fi

   INCREMENTS=$(( ($TOTAL_COMMITS / $BATCHES) - 1 ))

   for (( BATCH=BATCHES; BATCH>=1; BATCH-- ))
   do
     COMMIT_NUM=$(( $BATCH - $INCREMENTS ))
     COMMIT_SHA=$(git log -n $COMMIT_NUM --format=format:%H | tail -1)
     git push -u origin ${COMMIT_SHA}:refs/heads/main
   done
   git push -u origin main
   git push -u origin --all
   git push -u origin --tags
   ```

## Erreur : `HTTP 524 A timeout occurred` lors de l'import d'un projet {#error-http-524-a-timeout-occurred-when-importing-a-project}

Sur GitLab.com, l'import d'un projet peut échouer avec une erreur `HTTP 524 A timeout occurred`. Cette erreur peut survenir avec des archives de plusieurs gigaoctets.

Chaque envoi doit se terminer dans un délai imparti. Les archives volumineuses peuvent dépasser cette limite, ce qui ferme la connexion avant la fin de l'envoi.

Pour éviter cette erreur, hébergez l'archive à un emplacement HTTPS (par exemple, un bucket AWS S3) et laissez GitLab la télécharger lors de l'import. Utilisez l'un de ces endpoints :

- [`POST /api/v4/projects/remote-import`](../../../api/project_import_export.md#import-a-project-from-a-remote-archive) fonctionne avec n'importe quelle URL HTTPS, y compris les URL présignées S3.
- [`POST /api/v4/projects/remote-import-s3`](../../../api/project_import_export.md#import-a-project-from-an-aws-s3-bucket) fonctionne avec AWS S3 en utilisant des identifiants.

Comme GitLab télécharge l'archive en arrière-plan, la taille de l'archive n'entraîne pas de délai d'expiration.

## Échec du processus Sidekiq lors de l'export d'un projet {#sidekiq-process-fails-to-export-a-project}

Il arrive que le processus Sidekiq échoue lors de l'export d'un projet, par exemple s'il est interrompu pendant l'exécution.

Les utilisateurs de GitLab.com doivent [contacter le support](https://support.gitlab.com/hc/en-us/articles/11626483177756-GitLab-Support#contact-support) pour résoudre ce problème.

Les administrateurs GitLab Self-Managed peuvent utiliser la console Rails pour contourner le processus Sidekiq et déclencher manuellement l'export du projet :

```ruby
project = Project.find(1)
current_user = User.find_by(username: 'my-user-name')
RequestStore.begin!
ActiveRecord::Base.logger = Logger.new(STDOUT)
params = {}

::Projects::ImportExport::ExportService.new(project, current_user, params).execute(nil)
```

Cela rend l'export disponible via l'interface, mais ne déclenche pas l'envoi d'un e-mail à l'utilisateur. Pour déclencher manuellement l'export du projet et envoyer un e-mail :

```ruby
project = Project.find(1)
current_user = User.find_by(username: 'my-user-name')
RequestStore.begin!
ActiveRecord::Base.logger = Logger.new(STDOUT)
params = {}

ProjectExportWorker.new.perform(current_user.id, project.id)
```

## Exécuter manuellement les étapes d'export {#manually-execute-export-steps}

Vous exportez généralement un projet via [l'interface web](import_export.md#export-a-project-and-its-data) ou via l'[API d'import et d'export de projets](../../../api/project_import_export.md). L'export à l'aide de ces méthodes peut parfois échouer sans fournir suffisamment d'informations pour résoudre le problème. Dans ces cas, [ouvrez une session de console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session) et parcourez [tous les exporteurs définis](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/services/projects/import_export/export_service.rb). Exécutez chaque ligne individuellement, plutôt que de coller l'intégralité du bloc en une seule fois, afin de voir les erreurs renvoyées par chaque commande.

```ruby
# User needs to have permission to export
u = User.find_by_username('someuser')
p = Project.find_by_full_path('some/project')
e = Projects::ImportExport::ExportService.new(p,u)

e.send(:version_saver).send(:save)
e.send(:repo_saver).send(:save)
e.send(:avatar_saver).send(:save)
e.send(:project_tree_saver).send(:save)
e.send(:uploads_saver).send(:save)
e.send(:wiki_repo_saver).send(:save)
e.send(:lfs_saver).send(:save)
e.send(:snippets_repo_saver).send(:save)
e.send(:design_repo_saver).send(:save)
## continue using `e.send(:exporter_name).send(:save)` going through the list of exporters

# The following line should show you the export_path similar to /var/opt/gitlab/gitlab-rails/shared/tmp/gitlab_exports/@hashed/49/94/4994....
s = Gitlab::ImportExport::Saver.new(exportable: p, shared: p.import_export_shared, user: u)

# Prior to GitLab 17.0, the `user` parameter was not supported. If you encounter an
# error with the above or are unsure whether or not to supply the `user`
# argument, use the following check:
Gitlab::ImportExport::Saver.instance_method(:initialize).parameters.include?([:keyreq, :user])
# If the preceding check returns false, omit the user argument:
s = Gitlab::ImportExport::Saver.new(exportable: p, shared: p.import_export_shared)

# To try and upload use:
s.send(:compress_and_save)
s.send(:save_upload)
```

Une fois le projet envoyé avec succès, le projet exporté se trouve dans un fichier `.tar.gz` dans `/var/opt/gitlab/gitlab-rails/uploads/-/system/import_export_upload/export_file/`.

## Erreur : `PG::QueryCanceled: ERROR: canceling statement due to statement timeout` {#error-pgquerycanceled-error-canceling-statement-due-to-statement-timeout}

Certaines migrations peuvent expirer avec l'erreur : `PG::QueryCanceled: ERROR: canceling statement due to statement timeout`. Une façon d'éviter ce problème est de réduire la taille des lots de migration. Cela réduit la probabilité d'expiration d'une migration, mais ralentit les migrations.

Pour réduire la taille des lots, vous devez avoir un feature flag activé. Pour plus d'informations, consultez le [ticket 456948](https://gitlab.com/gitlab-org/gitlab/-/issues/456948).

## Erreur : `JSON exceeds 50 MB limit` {#error-json-exceeds-50-mb-limit}

Il est possible que vous obteniez l'erreur suivante lors de l'import d'un projet par export de fichiers :

```plaintext
JSON exceeds 50 MB limit
```

Cette erreur se produit lorsqu'un seul enregistrement dans l'export, tel qu'une merge request ou un ticket avec une description ou un diff volumineux, dépasse la limite de 50 Mo que l'import applique à chaque enregistrement.

Pour résoudre cette erreur, réduisez la taille de l'enregistrement concerné dans le projet source, puis exportez et importez à nouveau le projet.

## Erreur : `command exited with error code 15 and Unable to save [FILTERED] into [FILTERED]` {#error-command-exited-with-error-code-15-and-unable-to-save-filtered-into-filtered}

Il est possible que vous obteniez l'erreur suivante dans les journaux lors de la migration de projets par export de fichiers :

```plaintext
command exited with error code 15 and Unable to save [FILTERED] into [FILTERED]
```

Cette erreur se produit lors de l'export ou de l'import lorsque Sidekiq reçoit un signal `SIGTERM`, souvent lors de l'exécution de la commande `tar`.

Dans les environnements Kubernetes tels que GitLab.com et GitLab Dedicated, le système d'exploitation déclenche des signaux `SIGTERM` en raison d'un manque de mémoire ou d'espace disque, de déploiements de code ou de mises à niveau d'instances. Pour identifier la cause racine, un administrateur doit examiner pourquoi Kubernetes a arrêté l'instance.

Dans les environnements non-Kubernetes, cette erreur peut se produire si l'instance est arrêtée lors de l'exécution de la commande `tar`. Cependant, cette erreur ne se produit pas en raison d'un manque d'espace disque ; le manque de mémoire est donc la cause la plus probable.

Si vous obtenez cette erreur :

- Lors de l'export d'un fichier, GitLab relance l'export jusqu'à ce que le nombre maximum de tentatives soit atteint, puis marque l'export comme échoué. Pour GitLab.com, tentez l'export pendant le week-end, lorsque la charge sur l'instance est moins importante.
- Lors de l'import d'un fichier, vous devez relancer l'import vous-même. GitLab ne relance pas l'import automatiquement.

## Résolution des problèmes de performance {#troubleshooting-performance-issues}

Lisez les problèmes de performance actuels liés à Import/Export ci-dessous.

### Erreurs OOM {#oom-errors}

Les erreurs de mémoire insuffisante (OOM) sont généralement causées par le [Sidekiq memory killer](../../../administration/sidekiq/sidekiq_memory_killer.md) :

```shell
SIDEKIQ_MEMORY_KILLER_MAX_RSS = 2000000
SIDEKIQ_MEMORY_KILLER_HARD_LIMIT_RSS = 3000000
SIDEKIQ_MEMORY_KILLER_GRACE_TIME = 900
```

Un statut d'import `started` et les journaux Sidekiq suivants signalent un problème de mémoire :

```shell
WARN: Work still in progress <struct with JID>
```

### Délais d'expiration {#timeouts}

Les erreurs de délai d'expiration se produisent en raison de `Gitlab::Import::StuckProjectImportJobsWorker` qui marque le processus comme échoué :

```ruby
module Gitlab
  module Import
    class StuckProjectImportJobsWorker
      include Gitlab::Import::StuckImportJob
      # ...
    end
  end
end

module Gitlab
  module Import
    module StuckImportJob
      # ...
      IMPORT_JOBS_EXPIRATION = 15.hours.to_i
      # ...
      def perform
        stuck_imports_without_jid_count = mark_imports_without_jid_as_failed!
        stuck_imports_with_jid_count = mark_imports_with_jid_as_failed!

        track_metrics(stuck_imports_with_jid_count, stuck_imports_without_jid_count)
      end
      # ...
    end
  end
end
```

```shell
Marked stuck import jobs as failed. JIDs: xyz
```

```plaintext
  +-----------+    +-----------------------------------+
  |Export Job |--->| Calls ActiveRecord `as_json` and  |
  +-----------+    | `to_json` on all project models   |
                   +-----------------------------------+

  +-----------+    +-----------------------------------+
  |Import Job |--->| Loads all JSON in memory, then    |
  +-----------+    | inserts into the DB in batches    |
                   +-----------------------------------+
```

### Problèmes et solutions {#problems-and-solutions}

Chargement/dumping lent des modèles [JSON](https://gitlab.com/gitlab-org/gitlab/-/issues/25251) depuis la base de données :

- [Diviser le worker](https://gitlab.com/gitlab-org/gitlab/-/issues/25252)
- Export par lots
- Optimiser le SQL
- Abandonner les callbacks `ActiveRecord` (difficile)

Utilisation élevée de la mémoire (voir aussi quelques [analyses](https://gitlab.com/gitlab-org/gitlab/-/issues/18857)) :

- Point optimal de commit en base de données consommant moins de mémoire
- L'[API Netflix Fast JSON](https://github.com/Netflix/fast_jsonapi) pourrait aider
- Lecture/écriture par lots sur disque et dans tout SQL
