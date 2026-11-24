---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Outils de l'agent"
---

Les outils suivants sont disponibles pour les agents personnalisés.

## Outils disponibles dans l'interface Web et l'IDE {#tools-available-in-the-web-ui-and-ide}

{{< history >}}

- L'outil Get Previous Session Context a été [renommé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254136) en Get Session Context dans GitLab 19.4.

{{< /history >}}

| Nom | Outil | Description |
|------|------|-------------|
| Add Merge Request Reviewers | `add_merge_request_reviewers` | Ajouter des relecteurs à une merge request sans supprimer les relecteurs existants. |
| Add New Task | `add_new_task` | Ajouter une tâche. |
| Build Review Merge Request Context | `build_review_merge_request_context` | Construire un contexte de merge request complet pour la revue de code. |
| CI Linter | `ci_linter` | Valider les configurations YAML CI/CD par rapport aux règles de syntaxe CI/CD. |
| Confirm Vulnerability | `confirm_vulnerability` | Changer l'état d'une vulnérabilité dans un projet en `CONFIRMED`. |
| Create Branch | `create_branch` | Créer une branche dans un dépôt. |
| Create Commit | `create_commit` | Créer un commit avec plusieurs actions sur des fichiers dans un dépôt. |
| Create Epic | `create_epic` | Créer des epics dans un groupe. |
| Create Issue | `create_issue` | Créer des tickets dans un projet. |
| Create Issue Note | `create_issue_note` | Ajouter des notes à un ticket. |
| Create Merge Request | `create_merge_request` | Créer des merge requests dans un projet. |
| Create Merge Request Diff Note | `create_merge_request_diff_note` | Ajouter des notes diff inline à une merge request. Les actions rapides ne sont pas prises en charge. |
| Create Merge Request Note | `create_merge_request_note` | Ajouter des notes à une merge request. Les actions rapides ne sont pas prises en charge. |
| Create Plan | `create_plan` | Créer une liste de tâches. |
| Create Vulnerability Issue | `create_vulnerability_issue` | Créer un ticket lié aux vulnérabilités de sécurité dans un projet. |
| Create Work Item | `create_work_item` | Créer un élément de travail dans un groupe ou un projet. Les actions rapides ne sont pas prises en charge. |
| Create Work Item Note | `create_work_item_note` | Ajouter une note à un élément de travail. Les actions rapides ne sont pas prises en charge. |
| Dismiss Vulnerability | `dismiss_vulnerability` | Ignorer une vulnérabilité de sécurité dans un projet. |
| Extract Lines From Text | `extract_lines_from_text` | Extraire des lignes spécifiques d'un texte. |
| Get Commit | `get_commit` | Obtenir un commit depuis un projet. |
| Get Commit Comments | `get_commit_comments` | Obtenir les commentaires d'un commit dans un projet. |
| Get Commit Diff | `get_commit_diff` | Obtenir le diff d'un commit dans un projet. |
| Get Current User | `get_current_user` | Obtenir les informations suivantes sur l'utilisateur actuel : nom d'utilisateur, intitulé du poste et langues préférées. |
| Get Downstream Pipelines | `get_downstream_pipelines` | Obtenir les URL des pipelines downstream. |
| Get Epic | `get_epic` | Obtenir un epic dans un groupe. |
| Get Epic Note | `get_epic_note` | Obtenir une note depuis un epic. |
| Get Failing Bridge Jobs | `get_failing_bridge_jobs` | Obtenir les jobs bridge en échec dans un pipeline et l'URL de chaque pipeline downstream. |
| Get Issue | `get_issue` | Obtenir un ticket depuis un projet. |
| Get Issue Note | `get_issue_note` | Obtenir une note depuis un ticket. |
| Get Job Logs | `get_job_logs` | Obtenir la trace d'un job. |
| Get Merge Request | `get_merge_request` | Obtenir des détails sur une merge request. |
| Get Pipeline Errors | `get_pipeline_errors` | Obtenir les logs des jobs en échec depuis le dernier pipeline d'une merge request. |
| Get Pipeline Failing Jobs | `get_pipeline_failing_jobs` | Obtenir les identifiants des jobs en échec dans un pipeline. |
| Get Plan | `get_plan` | Obtenir une liste de tâches. |
| Get Project | `get_project` | Obtenir des détails sur un projet. |
| Get Repository File | `get_repository_file` | Obtenir le contenu d'un fichier depuis un dépôt distant. |
| Get Repository Files | `get_repository_files` | Obtenir le contenu de plusieurs fichiers depuis un dépôt en un seul appel. |
| Get Security Finding Details | `get_security_finding_details` | Obtenir les détails d'une vulnérabilité potentielle par son identifiant et l'identifiant du scan de pipeline qui l'a identifiée. |
| Get Session Context | `get_session_context` | Obtenir le contexte d'une session en cours ou terminée. |
| Get Vulnerability Details | `get_vulnerability_details` | Obtenir les informations suivantes sur une vulnérabilité spécifiée par son identifiant : informations de base sur la vulnérabilité, détails de localisation, données d'enrichissement CVE, informations sur le pipeline de détection et données détaillées du rapport de vulnérabilité. |
| Get Wiki Page | `get_wiki_page` | Obtenir une page wiki depuis un projet ou un groupe, y compris tous ses commentaires. |
| Get Work Item | `get_work_item` | Obtenir un élément de travail depuis un groupe ou un projet. |
| Get Work Item Notes | `get_work_item_notes` | Obtenir toutes les notes pour un élément de travail. |
| Get Work Item Statuses | `get_work_item_statuses` | Obtenir les statuts d'éléments de travail disponibles pour un groupe ou un projet. |
| GitLab API Get | `gitlab_api_get` | Effectuer des requêtes GET en lecture seule vers n'importe quel endpoint de l'API REST. |
| GitLab Blob Search | `gitlab_blob_search` | Rechercher le contenu de fichiers dans un groupe, un projet ou une instance. Pour effectuer une recherche dans un groupe ou dans une instance, vous devez activer la recherche [avancée](../../../integration/advanced_search/elasticsearch.md#enable-code-search-with-advanced-search) ou la recherche [de code exacte](../../../integration/zoekt/_index.md#enable-exact-code-search).  |
| GitLab Commit Search | `gitlab_commit_search` | Rechercher des commits dans un projet ou un groupe. |
| GitLab Documentation Search | `gitlab_documentation_search` | Rechercher des informations dans la documentation GitLab. |
| GitLab GraphQL | `gitlab_graphql` | Exécuter des requêtes GraphQL en lecture seule contre l'API GraphQL. |
| GitLab Group Project Search | `gitlab_group_project_search` | Rechercher des projets dans un groupe. |
| GitLab Issue Search | `gitlab_issue_search` | Rechercher des tickets dans un projet ou un groupe. |
| GitLab Merge Request Search | `gitlab_merge_request_search` | Rechercher des merge requests dans un projet ou un groupe. |
| GitLab Milestone Search | `gitlab_milestone_search` | Rechercher des jalons dans un projet ou un groupe. |
| GitLab Note Search | `gitlab_note_search` | Rechercher des notes dans un projet. |
| GitLab User Search | `gitlab__user_search` | Rechercher des utilisateurs dans un projet ou un groupe. |
| GitLab Wiki Blob Search | `gitlab_wiki_blob_search` | Rechercher le contenu des wikis dans un projet ou un groupe. |
| Link Vulnerability To Issue | `link_vulnerability_to_issue` | Associer un ticket aux vulnérabilités de sécurité dans un projet. |
| Link Vulnerability To Merge Request | `link_vulnerability_to_merge_request` | Associer une vulnérabilité de sécurité à une merge request dans un projet via GraphQL. |
| List All Merge Request Notes | `list_all_merge_request_notes` | Lister toutes les notes d'une merge request. |
| List Commits | `list_commits` | Lister les commits dans un projet. |
| List Epic Notes | `list_epic_notes` | Lister toutes les notes d'un epic. |
| List Epics | `list_epics` | Lister tous les epics d'un groupe et de ses sous-groupes. |
| List Group Audit Events | `list_group_audit_events` | Lister les événements d'audit pour un groupe. Vous devez disposer du rôle Propriétaire pour accéder aux événements d'audit du groupe. |
| List Instance Audit Events | `list_instance_audit_events` | Lister les événements d'audit au niveau de l'instance. Vous devez être administrateur pour consulter les événements d'audit de l'instance. |
| List Issue Notes | `list_issue_notes` | Lister toutes les notes d'un ticket. |
| List Issues | `list_issues` | Lister tous les tickets d'un projet. |
| List Merge Request Diffs | `list_merge_request_diffs` | Lister les diffs des fichiers modifiés dans une merge request. |
| List MR Discussions | `list_mr_discussions` | Lister les fils de discussion sur une merge request. |
| List Project Audit Events | `list_project_audit_events` | Lister les événements d'audit pour un projet. Vous devez disposer du rôle Propriétaire pour accéder aux événements d'audit du projet. |
| List Repository Tree | `list_repository_tree` | Lister les fichiers et répertoires dans un dépôt. |
| List Security Findings | `list_security_findings` | Lister les résultats de sécurité éphémères issus d'un scan de sécurité de pipeline spécifique. |
| List Vulnerabilities | `list_vulnerabilities` | Lister les vulnérabilités de sécurité dans un projet. |
| List Work Items | `list_work_items` | Lister les éléments de travail dans un projet ou un groupe. |
| Post SAST FP Analysis To GitLab | `post_sast_fp_analysis_to_gitlab` | Publier les résultats d'analyse de détection de faux positifs SAST. |
| Remove Task | `remove_task` | Supprimer une tâche d'une liste de tâches. |
| Reply To Discussion | `reply_to_discussion` | Répondre à un fil de discussion sur une merge request. |
| Revert To Detected Vulnerability | `revert_to_detected_vulnerability` | Rétablir l'état d'une vulnérabilité à `detected`. |
| Run GLQL Query | `run_glql_query` | Exécuter des requêtes GLQL pour les éléments de travail, les epics et les merge requests. |
| Run Tests | `run_tests` | Exécuter des commandes de test pour n'importe quel langage ou framework. |
| Set Discussion Resolved | `set_discussion_resolved` | Définir le statut de résolution d'un fil de discussion sur une merge request. |
| Set Task Status | `set_task_status` | Définir le statut d'une tâche. |
| Submit MR Review | `submit_mr_review` | Soumettre une revue de merge request avec des commentaires diff inline, un verdict et une note de synthèse facultative. |
| Update Epic | `update_epic` | Mettre à jour un epic dans un groupe. |
| Update Issue | `update_issue` | Mettre à jour un ticket dans un projet. |
| Update Merge Request | `update_merge_request` | Mettre à jour une merge request. Vous pouvez modifier la branche cible, éditer le titre ou même fermer la merge request. |
| Update Task Description | `update_task_description` | Mettre à jour la description d'une tâche. |
| Update Vulnerability Severity | `update_vulnerability_severity` | Mettre à jour le niveau de gravité des vulnérabilités dans un projet. |
| Update Work Item | `update_work_item` | Mettre à jour un élément de travail existant dans un groupe ou un projet. Les actions rapides ne sont pas prises en charge. |

## Outils disponibles dans l'IDE uniquement {#tools-available-in-the-ide-only}

| Nom | Outil | Description |
|------|------|-------------|
| Create File With Contents | `create_file_with_contents` | Créer un fichier et y écrire du contenu. |
| Edit File | `edit_file` | Modifier des fichiers existants. |
| Find Files | `find_files` | Rechercher des fichiers de manière récursive dans un projet. |
| Grep | `grep` | Rechercher des motifs de texte dans des fichiers de manière récursive. Cet outil respecte les règles du fichier `.gitignore`. |
| List Dir | `list_dir` | Lister les fichiers dans un répertoire relatif à la racine du projet. |
| Mkdir | `mkdir` | Créer un répertoire dans l'arborescence de travail actuelle. |
| Notify Me When | `notify_me_when` | Planifier la reprise automatique de l'agent lorsqu'une condition est remplie, par exemple lorsqu'un pipeline se termine. |
| Read File | `read_file` | Lire le contenu d'un fichier. |
| Read Files | `read_files` | Lire le contenu de fichiers. |
| Run Command | `run_command` | Exécuter des commandes bash, y compris des commandes Git, dans le répertoire de travail actuel. |
| Run Git Command | `run_git_command` (obsolète) | Exécuter des commandes Git dans le répertoire de travail actuel. Utilisez plutôt `run_command`. |
