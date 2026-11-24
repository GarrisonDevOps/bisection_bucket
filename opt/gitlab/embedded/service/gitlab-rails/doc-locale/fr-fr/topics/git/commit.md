---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Commandes et workflows courants.
title: "Indexer, commiter et pousser des modifications"
---

Lorsque vous apportez des modifications aux fichiers d'un dépôt, Git suit les modifications par rapport à la version la plus récente de la branche extraite. Vous pouvez utiliser les commandes Git pour examiner et commiter vos modifications dans la branche, et pousser votre travail vers GitLab.

## Ajouter et commiter des modifications locales {#add-and-commit-local-changes}

Lorsque vous êtes prêt à écrire vos modifications dans la branche, vous pouvez les commiter. Un commit inclut un commentaire qui enregistre des informations sur les modifications et constitue généralement le nouveau sommet de la branche.

Git n'inclut pas automatiquement dans un commit les fichiers que vous déplacez, modifiez ou supprimez. Cela vous évite d'inclure accidentellement une modification ou un fichier, comme un répertoire temporaire. Pour inclure des modifications dans un commit, indexez-les avec `git add`.

Pour indexer et commiter vos modifications :

1. Depuis votre dépôt, pour chaque fichier ou répertoire que vous souhaitez ajouter, exécutez :

   ```shell
   git add <file name or path>
   ```

   Pour indexer tous les fichiers du répertoire de travail courant, exécutez :

   ```shell
   git add .
   ```

1. Confirmez que les fichiers ont été ajoutés à l'index :

   ```shell
   git status
   ```

   Les fichiers s'affichent en vert.
1. Pour commiter les fichiers indexés :

   ```shell
   git commit -m "<comment that describes the changes>"
   ```

Les modifications sont commitées dans la branche.

### Rédiger un bon message de commit {#write-a-good-commit-message}

Les directives publiées par Chris Beams dans [How to Write a Git Commit Message](https://cbea.ms/git-commit/) vous aident à rédiger un bon message de commit :

- Le sujet et le corps du commit doivent être séparés par une ligne vide.
- Le sujet du commit doit commencer par une majuscule.
- Le sujet du commit ne doit pas dépasser 72 caractères.
- Le sujet du commit ne doit pas se terminer par un point.
- Le corps du commit ne doit pas contenir plus de 72 caractères par ligne.
- Le sujet ou le corps du commit ne doit pas contenir d'emoji.
- Les commits qui modifient 30 lignes ou plus sur au moins 3 fichiers doivent décrire ces modifications dans le corps du commit.
- Utilisez les URL complètes pour les tickets, les jalons et les merge requests plutôt que des références abrégées, car elles s'affichent en texte brut en dehors de GitLab.
- La merge request ne doit pas contenir plus de 10 messages de commit.
- Le sujet du commit doit contenir au moins 3 mots.

## Commiter toutes les modifications {#commit-all-changes}

Vous pouvez indexer toutes vos modifications et les commiter en une seule commande :

```shell
git commit -a -m "<comment that describes the changes>"
```

Veillez à ce que votre commit n'inclue pas de fichiers que vous ne souhaitez pas enregistrer dans le dépôt distant. En règle générale, vérifiez toujours le statut de votre dépôt local avant de commiter des modifications.

## Envoyer des modifications à GitLab {#send-changes-to-gitlab}

Pour pousser toutes les modifications locales vers le dépôt distant :

```shell
git push <remote> <name-of-branch>
```

Par exemple, pour pousser vos commits locaux vers la branche `main` du remote `origin` :

```shell
git push origin main
```

Parfois, Git ne vous permet pas de pousser vers un dépôt. Dans ce cas, vous devez [forcer une mise à jour](git_rebase.md#force-push-to-a-remote-branch).

## Options de push {#push-options}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lorsque vous poussez des modifications vers une branche, vous pouvez utiliser les [options de push Git](https://git-scm.com/docs/git-push#Documentation/git-push.txt--oltoptiongt) côté client. Dans Git 2.10 et versions ultérieures, utilisez les options de push Git pour :

- [Ignorer les jobs CI](#push-options-for-gitlab-cicd)
- [Pousser vers des merge requests](#push-options-for-merge-requests)

Dans Git 2.18 et versions ultérieures, vous pouvez utiliser le format long (`--push-option`) ou le format court `-o` :

```shell
git push -o <push_option>
```

Dans Git 2.10 à 2.17, vous devez utiliser le format long :

```shell
git push --push-option=<push_option>
```

Pour les contrôles côté serveur et l'application des bonnes pratiques, consultez les [règles de push](../../user/project/repository/push_rules.md) et les [hooks serveur](../../administration/server_hooks.md).

### Options de push pour GitLab CI/CD {#push-options-for-gitlab-cicd}

Vous pouvez utiliser les options de push pour ignorer un pipeline CI/CD ou transmettre des variables CI/CD.

> [!note]
> Les options de push ne sont pas disponibles pour les pipelines de merge request. Pour plus d'informations, consultez le [ticket 373212](https://gitlab.com/gitlab-org/gitlab/-/issues/373212).

| Option de push                    | Description | Exemple |
|--------------------------------|-------------|---------|
| `ci.input=<name>=<value>`      | Transmet des paramètres d'entrée au pipeline. | `git push -o ci.input='stage=test' -o ci.input='security_scan=false'`. Entrée de tableau : `git push -o ci.input='my_array=["string", "double", "quotes"]'` |
| `ci.skip`                      | Ignore le pipeline pour ce push. Affecte uniquement les pipelines de branche, pas les [pipelines de merge request](../../ci/pipelines/merge_request_pipelines.md). N'ignore pas les intégrations CI/CD telles que Jenkins. | `git push -o ci.skip` |
| `ci.no_pipeline`               | Empêche la création de tout pipeline pour le dernier push.   | `git push -o ci.no_pipeline` |
| `ci.variable="<name>=<value>"` | Définit des [variables CI/CD](../../ci/variables/_index.md) pour le pipeline. Affecte uniquement les pipelines de branche, pas les [pipelines de merge request](../../ci/pipelines/merge_request_pipelines.md). | `git push -o ci.variable="MAX_RETRIES=10" -o ci.variable="MAX_TIME=600"` |

### Options de push pour les intégrations {#push-options-for-integrations}

Vous pouvez utiliser les options de push pour ignorer les pipelines CI/CD des intégrations.

| Option de push                    | Description | Exemple |
|--------------------------------|-------------|---------|
| `integrations.skip_ci`         | Ignore les événements de push pour les intégrations CI/CD, telles qu'Atlassian Bamboo, Buildkite, Drone, Jenkins et JetBrains TeamCity. | `git push -o integrations.skip_ci` |

### Options de push pour les merge requests {#push-options-for-merge-requests}

Les options de push Git peuvent effectuer des actions sur les merge requests lors de la poussée de modifications :

| Option de push                                  | Description |
|----------------------------------------------|-------------|
| `merge_request.create`                       | Crée une nouvelle merge request pour la branche poussée. Lors d'un push depuis la branche par défaut, vous devez spécifier une branche cible à l'aide de l'option `merge_request.target` pour créer une merge request. |
| `merge_request.target=<branch_name>`         | Définit la cible de la merge request sur une branche particulière, par exemple : `git push -o merge_request.target=branch_name`. Obligatoire lors de la création d'une merge request depuis la branche par défaut. |
| `merge_request.target_project=<project>`     | Définit la cible de la merge request sur un projet amont particulier, par exemple : `git push -o merge_request.target_project=path/to/project`. |
| `merge_request.merge_when_pipeline_succeeds` | [Déprécié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/185368) dans GitLab 17.11 au profit de l'option `auto_merge`. |
| `merge_request.auto_merge` | Configure la merge request pour la [fusion automatique](../../user/project/merge_requests/auto_merge.md). |
| `merge_request.remove_source_branch`         | Configure la merge request pour supprimer la branche source lors de la fusion. |
| `merge_request.squash`                       | Configure la merge request pour squasher tous les commits en un seul commit lors de la fusion. Introduit dans [GitLab 17.2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/158778). |
| `merge_request.title="<title>"`              | Définit le titre de la merge request. Par exemple : `git push -o merge_request.title="The title I want"`. |
| `merge_request.description="<description>"`  | Définit la description de la merge request. Par exemple : `git push -o merge_request.description="The description I want"`. |
| `merge_request.draft`                        | Marque la merge request comme brouillon. Par exemple : `git push -o merge_request.draft`. |
| `merge_request.milestone="<milestone>"`      | Définit le jalon de la merge request. Par exemple : `git push -o merge_request.milestone="3.0"`. |
| `merge_request.label="<label>"`              | Ajoute des labels à la merge request. Si le label n'existe pas, il est créé. Par exemple, pour deux labels : `git push -o merge_request.label="label1" -o merge_request.label="label2"`. |
| `merge_request.unlabel="<label>"`            | Supprime des labels de la merge request. Par exemple, pour deux labels : `git push -o merge_request.unlabel="label1" -o merge_request.unlabel="label2"`. |
| `merge_request.assign="<user>"`              | Assigne des utilisateurs à la merge request. Accepte le nom d'utilisateur ou l'identifiant utilisateur. Par exemple, pour deux utilisateurs : `git push -o merge_request.assign="user1" -o merge_request.assign="user2"`. |
| `merge_request.unassign="<user>"`            | Retire les utilisateurs assignés de la merge request. Accepte le nom d'utilisateur ou l'identifiant utilisateur. Par exemple, pour deux utilisateurs : `git push -o merge_request.unassign="user1" -o merge_request.unassign="user2"`. |

### Options de push pour la protection push des secrets {#push-options-for-secret-push-protection}

Vous pouvez utiliser les options de push pour ignorer la [protection push des secrets](../../user/application_security/secret_detection/secret_push_protection/_index.md).

| Option de push                    | Description | Exemple |
|--------------------------------|-------------|---------|
| `secret_push_protection.skip_all` | Ne pas effectuer la protection push des secrets pour tout commit de ce push. | `git push -o secret_push_protection.skip_all` |

### Options de push pour les politiques de sécurité {#push-options-for-security-policy}

Vous pouvez utiliser les options de push pour [contourner les politiques de sécurité](../../user/application_security/policies/merge_request_approval_policies.md#allowing-users-to-bypass-security-policies).

| Option de push                    | Description | Exemple |
|--------------------------------|-------------|---------|
| `security_policy.bypass_reason` | Définit la raison du contournement pour la politique de sécurité. | `git push -o security_policy.bypass_reason="Hot fix"` |

### Options de push pour l'intégration GitGuardian {#push-options-for-gitguardian-integration}

Vous pouvez utiliser la même [option de push pour la protection push des secrets](#push-options-for-secret-push-protection) pour ignorer la détection des secrets GitGuardian.

| Option de push                    | Description | Exemple |
|--------------------------------|-------------|---------|
| `secret_detection.skip_all` | Déprécié dans GitLab 17.2. Utilisez plutôt `secret_push_protection.skip_all`. | `git push -o secret_detection.skip_all` |
| `secret_push_protection.skip_all` | Ne pas effectuer la détection des secrets GitGuardian. | `git push -o secret_push_protection.skip_all` |

### Formats des options de push {#formats-for-push-options}

Si votre option de push nécessite un texte contenant des espaces, placez le texte entre guillemets doubles (`"`). Vous pouvez omettre les guillemets s'il n'y a pas d'espaces. Quelques exemples :

```shell
git push -o merge_request.label="Label with spaces"
git push -o merge_request.label=Label-with-no-spaces
```

Pour combiner des options de push afin d'accomplir plusieurs tâches à la fois, utilisez plusieurs indicateurs `-o` (ou `--push-option`). Cette commande crée une nouvelle merge request, cible une branche (`my-target-branch`) et active la fusion automatique :

```shell
git push -o merge_request.create -o merge_request.target=my-target-branch -o merge_request.auto_merge
```

Pour créer une nouvelle merge request depuis la branche par défaut en ciblant une branche différente :

```shell
git push -o merge_request.create -o merge_request.target=feature-branch
```

### Sauts de ligne dans les valeurs des options de push {#newlines-in-push-option-values}

Les valeurs des options de push ne peuvent pas contenir de caractères de saut de ligne littéraux. Si vous transmettez directement une valeur multiligne, Git renvoie l'erreur suivante :

```plaintext
fatal: push options must not have new line characters
```

Pour inclure des sauts de ligne dans les valeurs des options de push (par exemple, dans une description de merge request), utilisez la séquence d'échappement `\n` à la place d'un saut de ligne littéral :

```shell
git push origin my-branch \
  -o merge_request.create \
  -o merge_request.title="My feature" \
  -o merge_request.description="# Summary\nDo something.\n\n# Testing\nDeploy this on your box."
```

GitLab convertit les séquences `\n` en sauts de ligne dans la description de la merge request.

Pour séparer des paragraphes sans saut de ligne, utilisez des balises de paragraphe HTML à la place de `\n` :

```shell
git push origin my-branch \
  -o merge_request.create \
  -o merge_request.description="<p>First paragraph</p><p>Second paragraph</p>"
```

### Créer des alias Git pour le push {#create-git-aliases-for-pushing}

L'ajout d'options de push aux commandes Git peut générer des commandes très longues. Si vous utilisez fréquemment les mêmes options de push, créez des alias Git pour ces options. Les alias Git sont des raccourcis en ligne de commande pour les commandes Git plus longues.

Pour créer et utiliser un alias Git pour l'[option de push Git de fusion automatique](#push-options-for-merge-requests) :

1. Dans votre fenêtre de terminal, exécutez cette commande :

   ```shell
   git config --global alias.mwps "push -o merge_request.create -o merge_request.target=main -o merge_request.auto_merge"
   ```

1. Pour utiliser l'alias afin de pousser une branche locale qui cible la branche par défaut (`main`) et fusionne automatiquement, exécutez cette commande :

   ```shell
   git mwps origin <local-branch-name>
   ```

## Sujets connexes {#related-topics}

- [Commandes Git courantes](commands.md)
