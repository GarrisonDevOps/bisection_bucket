---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Dépannage des projets
description: "Résolution de problèmes, tickets courants, débogage et résolution d'erreurs."
---

Lorsque vous travaillez avec des projets, vous pouvez rencontrer les tickets suivants ou avoir besoin de méthodes alternatives pour accomplir certaines tâches.

## `An error occurred while fetching commit data` {#an-error-occurred-while-fetching-commit-data}

Lorsque vous visitez un projet, le message `An error occurred while fetching commit data` peut s'afficher si vous utilisez un bloqueur de publicités dans votre navigateur. La solution consiste à désactiver votre bloqueur de publicités pour l'instance GitLab à laquelle vous tentez d'accéder.

## Rechercher des projets à l'aide d'une requête SQL {#find-projects-using-an-sql-query}

Dans [une session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session), vous pouvez rechercher et stocker un tableau de projets à partir d'une requête SQL :

```ruby
# Finds projects that end with '%ject'
projects = Project.find_by_sql("SELECT * FROM projects WHERE name LIKE '%ject'")
=> [#<Project id:12 root/my-first-project>>, #<Project id:13 root/my-second-project>>]
```

## Vider le cache d'un projet ou d'un dépôt {#clear-a-projects-or-repositorys-cache}

Si un projet ou un dépôt a été mis à jour mais que l'état n'est pas reflété dans l'interface utilisateur, vous devrez peut-être vider le cache du projet ou du dépôt. Vous pouvez le faire via [une session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session) et l'une des options suivantes :

> [!warning]
> Les commandes qui modifient des données peuvent causer des dommages si elles ne sont pas exécutées correctement ou dans les bonnes conditions. Exécutez toujours les commandes dans un environnement de test en premier et disposez d'une instance de sauvegarde prête à être restaurée.

```ruby
## Clear project cache
ProjectCacheWorker.perform_async(project.id)

## Clear repository .exists? cache
project.repository.expire_exists_cache
```

## Rechercher les projets en attente de suppression {#find-projects-that-are-pending-deletion}

Si vous avez besoin de trouver tous les projets marqués pour suppression mais qui n'ont pas encore été supprimés, [démarrez une session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session) et exécutez la commande suivante :

```ruby
projects = Project.where(pending_delete: true)
projects.each do |p|
  puts "Project ID: #{p.id}"
  puts "Project name: #{p.name}"
  puts "Repository path: #{p.repository.full_path}"
end
```

### Transférer un projet via la console {#transfer-a-project-using-console}

Si le transfert d'un projet via l'interface utilisateur ou l'API ne fonctionne pas, vous pouvez tenter le transfert dans une [session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session).

```ruby
p = Project.find_by_full_path('<project_path>')

# To set the owner of the project
current_user = p.creator

# Namespace where you want this to be moved
namespace = Namespace.find_by_full_path("<new_namespace>")

Projects::TransferService.new(p, current_user).execute(namespace)
```

## Transfert de projet bloqué à l'état `transfer_in_progress` ou `transfer_scheduled` {#project-transfer-stuck-in-transfer_in_progress-or-transfer_scheduled-state}

Un transfert de projet peut se bloquer lorsque le job de transfert asynchrone échoue, par exemple en raison d'une contention de verrou ou de délais d'expiration de requête. Réessayer le transfert renvoie :

`Unable to initiate transfer. The project may already have a transfer in progress.`

Dans GitLab 19.1 et versions ultérieures, réessayez le transfert. GitLab replanifie le transfert même lorsque l'espace de nommage du projet est encore à l'état `transfer_in_progress` ou `transfer_scheduled`.

Dans les versions de GitLab antérieures à 19.1, annulez l'état de transfert obsolète dans une [session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session) avant de réessayer le transfert :

> [!warning]
> Les commandes qui modifient des données peuvent causer des dommages si elles ne sont pas exécutées correctement ou dans les bonnes conditions. Exécutez toujours les commandes dans un environnement de test en premier et disposez d'une instance de sauvegarde prête à être restaurée.

```ruby
Project.find_by_full_path('<group>/<project_name>').project_namespace.cancel_transfer!
```

## Supprimer un projet via la console {#delete-a-project-using-console}

Si un projet ne peut pas être supprimé, vous pouvez tenter de le supprimer via la [console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session).

> [!warning]
> Les commandes qui modifient des données peuvent causer des dommages si elles ne sont pas exécutées correctement ou dans les bonnes conditions. Exécutez toujours les commandes dans un environnement de test en premier et disposez d'une instance de sauvegarde prête à être restaurée.

```ruby
project = Project.find_by_full_path('<project_path>')
user = User.find_by_username('<username>')
Projects::DestroyService.new(project, user, {}).execute
```

En cas d'échec, affichez la raison de l'erreur avec :

```ruby
project = Project.find_by_full_path('<project_path>')
project.deletion_error
```

## Activer ou désactiver une fonctionnalité pour tous les projets d'un groupe {#toggle-a-feature-for-all-projects-within-a-group}

Bien que l'activation ou la désactivation d'une fonctionnalité dans un projet puisse être effectuée via l'[API des projets](../../api/projects.md), vous pourriez avoir besoin de le faire pour un grand nombre de projets.

Pour activer ou désactiver une fonctionnalité spécifique, vous pouvez [démarrer une session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session) et exécuter la fonction suivante :

> [!warning]
> Les commandes qui modifient des données peuvent causer des dommages si elles ne sont pas exécutées correctement ou dans les bonnes conditions. Exécutez toujours les commandes dans un environnement de test en premier et disposez d'une instance de sauvegarde prête à être restaurée.

```ruby
projects = Group.find_by_name('_group_name').projects
projects.each do |p|
  ## replace <feature-name> with the appropriate feature name in all instances
  state = p.<feature-name>

  if state != 0
    puts "#{p.name} has <feature-name> already enabled. Skipping..."
  else
    puts "#{p.name} didn't have <feature-name> enabled. Enabling..."
    p.project_feature.update!(<feature-name>: ProjectFeature::PRIVATE)
  end
end
```

Pour trouver les fonctionnalités pouvant être activées ou désactivées, exécutez `pp p.project_feature`. Les niveaux de permission disponibles sont répertoriés dans [concerns/featurable.rb](https://gitlab.com/gitlab-org/gitlab/blob/master/app/models/concerns/featurable.rb).

## Base de connaissances du support {#support-knowledge-base}

Si vous rencontrez encore des problèmes, consultez la [base de connaissances du support GitLab](https://support.gitlab.com/hc/en-us/).
