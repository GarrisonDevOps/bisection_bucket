---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Utiliser le wiki avec votre workflow de planification
description: "Utilisez GitLab Wiki avec votre workflow de planification. Connectez la documentation aux epics, aux tickets et aux tableaux."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Wiki fonctionne avec vos outils de planification. Ce n'est pas un outil séparé. Vous pouvez lier des pages wiki à des epics, des tickets et des tableaux. Grâce aux vues intégrées alimentées par le GitLab Query Language (GLQL), vos pages wiki peuvent afficher des vues en direct et à mise à jour automatique des tickets et des éléments de travail, transformant ainsi la documentation en tableaux de bord dynamiques. Découvrez comment connecter le wiki aux tickets, aux epics et aux tableaux pour créer un workflow fluide où documentation et planification fonctionnent ensemble.

Un wiki enrichit vos outils de planification en vous offrant :

- Espace de documentation enrichi : exigences complexes, décisions de conception et documentation des processus qui ne s'intègrent pas dans les descriptions de tickets.
- Connaissances versionnées : suivez les modifications apportées aux spécifications et aux décisions au fil du temps.
- Vues de données en direct : intégrez des requêtes GLQL pour afficher les données des tickets et des éléments de travail en temps réel directement dans les pages wiki.
- Contexte durable : conservez le « pourquoi » derrière les décisions après la clôture des tickets.
- Référence centrale : source unique de vérité pour les processus, les standards et les accords de l'équipe.
- Mise en forme flexible : tableaux, diagrammes et contenu long format avec prise en charge complète de Markdown.
- Contrôle d'accès intégré : les wikis utilisent le système de rôles et de permissions existant dans GitLab, de sorte que les membres de l'équipe disposent automatiquement d'un accès wiki approprié en fonction de leurs rôles dans le projet, sans authentification séparée.

## Prérequis {#prerequisites}

Pour utiliser efficacement ce guide, vous devez être familiarisé avec :

- [GitLab Wiki](_index.md)
- [Markdown GitLab Flavored](../../markdown.md)
- Créer et gérer différents éléments de travail, tels que les [tickets](../issues/_index.md) et les [epics](../../group/epics/_index.md)

## Connecter des pages wiki aux éléments de travail {#connect-wiki-pages-to-work-items}

Créez des liens entre la documentation wiki et vos éléments de planification pour construire un réseau de connaissances connecté.

### Lier la documentation wiki aux epics {#link-wiki-documentation-to-epics}

Les epics nécessitent souvent des spécifications détaillées trop longues pour une description d'epic. Conservez la documentation complète dans un wiki :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Planification** > **Wiki**.
1. Créez une page wiki avec vos exigences détaillées (par exemple, avec le slug `product-requirements`).
1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le groupe de votre projet.
1. Sélectionnez **Planification** > **Éléments de travail**.
1. Dans la barre de filtres, sélectionnez le filtre **Type**, l'opérateur **est**, et la valeur **Épopée**.
1. Identifiez l'epic souhaité et sélectionnez son titre.
1. Dans la description de l'epic, créez un lien vers la page wiki :

   ```markdown
   ## Requirements

   See full specification: [[product-requirements]]

   Or with custom text: [[Full PRD|product-requirements]]

   Or use the full URL:
   [Full PRD](https://gitlab.example.com/group/project/-/wikis/product-requirements)
   ```

1. Dans la page wiki, créez un lien de retour vers l'epic :

   ```markdown
   Related epic: &123
   ```

Exemples d'utilisation :

- Documents d'exigences produit (PRD)
- Spécifications de conception technique
- Résultats de recherche utilisateur
- Analyse concurrentielle
- Métriques de succès et KPI

### Référencer le wiki depuis les tickets {#reference-wiki-from-issues}

Liez les tickets aux pages wiki pour les détails d'implémentation, les standards et les guides :

```markdown
## Implementation notes

Follow our [[API-design-standards]] when implementing this endpoint.

For local setup, see [[Development Setup Guide|development-environment-setup]].

Definition of Done: [[team-dod]]
```

Exemples d'utilisation :

- Standards de codage et guides de style
- Configuration de l'environnement de développement
- Procédures de test
- Runbooks de déploiement
- Guides de dépannage
- Documentation d'intégration

### Lier le wiki aux éléments de travail {#link-from-wiki-to-work-items}

Référencez les tickets et les epics directement dans les pages wiki :

```markdown
## Current sprint goals

- Implement user authentication: #1234
- Fix performance regression: #1235
- Update API documentation: #1236

## Q3 roadmap

Major initiatives:
- Authentication overhaul: &10
- Performance improvements: &11
- API v2 release: &12
```

### Références wiki inter-projets {#cross-project-wiki-references}

Créez des liens vers des pages wiki dans d'autres projets :

```markdown
## Related documentation

See the backend team's API guide: [[backend/api:api-standards]]

Or use the alternative syntax: [wiki_page:backend/api:api-standards]

With custom text: [[Backend API Standards|backend/api:api-standards]]
```

## Créer des tableaux de bord dynamiques avec des vues intégrées {#create-dynamic-dashboards-with-embedded-views}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/14767) dans GitLab 17.4 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `glql_integration`. Fonctionnalité désactivée par défaut.
- Activé sur GitLab.com dans GitLab 17.4 pour un sous-ensemble de groupes et de projets.
- [Passage](https://gitlab.com/gitlab-org/gitlab/-/issues/476990) de la version expérimentale à la version bêta dans GitLab 17.10.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/work_items/476990) dans GitLab 17.10.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/554870) dans GitLab 18.3. Suppression du feature flag `glql_integration`.

{{< /history >}}

Transformez vos pages wiki en tableaux de bord en direct grâce au [GitLab Query Language (GLQL)](../../glql/_index.md). Les vues intégrées se mettent automatiquement à jour lorsque les données changent, offrant une visibilité en temps réel sur vos données de planification sans quitter le wiki.

> [!note]
> Les vues intégrées ont des considérations de performance. Les requêtes volumineuses peuvent expirer ou être soumises à une limite de débit. Si vous rencontrez des délais d'expiration, réduisez la portée de votre requête en ajoutant davantage de filtres ou en réduisant le paramètre `limit`.

### Syntaxe de base des vues intégrées {#basic-embedded-view-syntax}

Pour intégrer une requête GLQL, utilisez un bloc de code avec `glql` comme identifiant de langage :

````yaml
```glql
display: table
title: Sprint 18.5 Dashboard
description: Current sprint work items
fields: title, assignee, state, health, labels, milestone, updated
limit: 20
sort: updated desc
query: project = "gitlab-org/gitlab" and milestone = "18.5" and opened = true
```
````

Cela crée un tableau en direct affichant tous les tickets ouverts du jalon actuel, mis à jour automatiquement à mesure que les tickets sont créés, modifiés ou fermés.

### Exemples de tableaux de bord de planification {#planning-dashboard-examples}

Créez des tableaux de bord de planification complets directement dans vos pages wiki.

> [!note]
> Dans les exemples de cette section, remplacez `project = "group/project"` par le chemin réel de votre projet, par exemple `project = "gitlab-org/gitlab"` ou `project = "my-team/my-project"`.

Prérequis :

- Vous devez disposer des permissions nécessaires pour consulter les tickets et les éléments de travail interrogés.

Tableau de bord de vue d'ensemble du sprint :

````yaml
```glql
display: table
title: Sprint Overview
description: All work for the current sprint
fields: title, assignee, state, labels("priority::*") as "Priority", health, due
limit: 30
sort: due asc
query: project = "group/project" and milestone = "Current Sprint" and opened = true
```
````

Outil de suivi des bugs critiques :

````yaml
```glql
display: table
title: Critical Bugs
description: High-priority bugs requiring immediate attention
fields: title, assignee, labels, created, updated
limit: 10
query: project = "group/project" and label = "bug" and label = "severity::1" and opened = true
```
````

Vue de la charge de travail de l'équipe :

````yaml
```glql
display: list
title: Team Work In Progress
description: Active work items by team member
fields: title, assignee, milestone, due
limit: 15
sort: assignee asc
query: project = "group/project" and assignee in (alice, bob, charlie) and label = "workflow::in dev"
```
````

Liste de tâches personnelle :

````yaml
```glql
display: orderedList
title: My Tasks
description: Tasks assigned to me, sorted by priority
fields: title, labels("priority::*") as "Priority", due
limit: 10
sort: due asc
query: type = Task and assignee = currentUser() and opened = true
```
````

Les vues intégrées prennent en charge :

- Formats d'affichage multiples : `table`, `list` ou `orderedList`
- Champs personnalisés : choisissez les champs à afficher
- Tri : triez par n'importe quel champ dans l'ordre croissant ou décroissant
- Filtrage : utilisez des requêtes complexes avec plusieurs conditions
- Pagination : chargez des résultats supplémentaires avec **Charger davantage**
- Fonctions dynamiques : utilisez `currentUser()` pour les vues personnalisées et `today()` pour les requêtes basées sur la date

## Workflows de planification avec le wiki {#planning-workflows-with-wiki}

### Planification et exécution du sprint {#sprint-planning-and-execution}

Créez un flux de documentation connecté tout au long de votre sprint :

#### Planification pré-sprint {#pre-sprint-planning}

1. Collecte des exigences : documentez les exigences détaillées dans le wiki.
1. Création d'epics : créez des epics qui référencent les spécifications du wiki.
1. Décomposition des stories : liez les tickets à la documentation wiki pertinente.
1. Notes d'estimation : documentez le raisonnement d'estimation dans le wiki.

#### Pendant le sprint {#during-sprint}

- Réunions quotidiennes (stand-ups) : créez des pages wiki quotidiennes avec des liens vers les tickets bloqués.
- Décisions techniques : documentez les décisions de conception avec des liens vers les tickets d'implémentation.
- Obstacles : suivez les blocages dans le wiki avec des références aux tickets.

#### Post-sprint {#post-sprint}

- Rétrospectives : créez des pages wiki de rétrospective qui référencent :
  - Tickets terminés
  - Métriques de vélocité
  - Actions à mener (sous forme de nouveaux tickets)
  - Leçons apprises

### Documentation de planification à long terme {#long-term-planning-documentation}

Maintenez une documentation stratégique connectée à votre roadmap :

#### Structure de la documentation du roadmap {#roadmap-documentation-structure}

```plaintext
roadmap/
├── 2025-strategy
├── q1-okrs
├── q2-okrs
├── architecture-decisions/
│   ├── adr-001-microservices
│   ├── adr-002-authentication
└── technical-debt-registry
```

Chaque page est liée aux epics pertinents et suit la progression via des références aux tickets.

#### Registres de décisions d'architecture {#architecture-decision-records}

Documentez les décisions techniques avec traçabilité. Vous pouvez utiliser un modèle similaire à celui-ci :

```markdown
# ADR-001: Adopt microservices architecture

## Status

Accepted

## Context

[Detailed context...]

## Decision

[Decision details...]

## Consequences

[Impact analysis...]

## Implementation

- Infrastructure epic: &50
- Service extraction: #2001, #2002, #2003
- Monitoring setup: #2004
```

### Collaboration transfonctionnelle {#cross-functional-collaboration}

Utilisez le wiki comme hub de collaboration pour les équipes transfonctionnelles :

#### Documentation de conception {#design-documentation}

- Liez les spécifications de conception aux tickets d'implémentation
- Maintenez des bibliothèques de composants avec des exemples d'utilisation
- Documentez les décisions de conception avec des références aux epics

#### Documentation API {#api-documentation}

- Générez une documentation API qui est liée aux tickets d'implémentation
- Maintenez les informations de versionnage avec des références aux jalons
- Incluez des exemples de code liés aux tickets de test

#### Plans de test QA {#qa-test-plans}

- Stratégies de test liées aux exigences des epics
- Référentiels de cas de test avec traçabilité des tickets
- Documentation des patterns de bugs avec des exemples de tickets

## Modèles de navigation et de découverte {#navigation-and-discovery-patterns}

### Rendre le wiki découvrable depuis les tickets et les tableaux {#make-wiki-discoverable-from-issues-and-boards}

#### Modèles de tickets et d'epics {#issue-and-epic-templates}

Incluez des références wiki dans vos modèles :

```markdown
## Prerequisites

- [ ] Review [[contribution-guidelines]]
- [ ] Check [[security-checklist]]
- [ ] Read relevant documentation in [[project-wiki-home]]

## Implementation

- [ ] Follow [[coding-standards]]
- [ ] Update [[api-documentation]] if needed
- [ ] Add tests per [[testing-guidelines]]
```

#### Descriptions des jalons {#milestone-descriptions}

Créez des liens vers les documents de planification wiki :

```markdown
## Milestone 18.5

Sprint dates: 2025-02-01 to 2025-02-14

- [[Sprint 18.5 Goals|sprint-18-5-goals]]
- [[Sprint 18.5 Capacity|sprint-18-5-capacity]]
- [[Known Issues|known-issues-and-workarounds]]
```

#### Descriptions des tableaux {#board-descriptions}

Référencez la documentation du workflow wiki :

```markdown
This board follows our [[Kanban Workflow Guide|kanban-workflow-guide]].

For column definitions, see [[Board Column Definitions|board-column-definitions]].
```

### Exposer les éléments de travail dans le wiki {#surface-work-items-in-wiki}

#### Créer des pages d'index {#create-index-pages}

Créez des pages wiki qui rassemblent les tickets associés :

```markdown
# Open bugs dashboard

## Critical (P1)

- #1001 - Database connection timeout
- #1002 - Authentication bypass

## High (P2)

- #1003 - Performance degradation
- #1004 - UI rendering issue

## By component

### Authentication

- #1001, #1005, #1009

### API

- #1002, #1006, #1010
```

#### Utiliser une structure wiki hiérarchique {#use-hierarchical-wiki-structure}

Organisez les pages wiki avec des dossiers et des liens relatifs :

```markdown
# Team handbook

## Processes

- [Sprint Planning](processes/sprint-planning) - How we plan sprints
- [Code Review](processes/code-review) - Review standards and SLAs
- [Incident Response](processes/incident-response) - On-call procedures

## Go up to parent page

[Back to Documentation](../documentation)
```

## Exemples pratiques {#practical-examples}

### Exemple 1 : workflow de développement de fonctionnalité {#example-1-feature-development-workflow}

Un cycle complet de développement de fonctionnalité utilisant l'intégration wiki :

1. Chef de produit :

   - Crée la page wiki `feature-x-prd` avec les études de marché.
   - Crée l'epic &100 avec le lien : `[[Feature X PRD|feature-x-prd]]`.
   - Ajoute les critères d'acceptation dans le wiki.

1. Responsable technique :

   - Crée la page wiki `feature-x-technical-design`.
   - Lie le document de conception à l'epic &100.
   - Crée les tickets d'implémentation #201-205 avec des références wiki.

1. Développeurs :

   - Référencent le document de conception wiki dans les descriptions de merge requests.
   - Mettent à jour le wiki avec les modifications de décisions.
   - Lient les tickets aux guides de dépannage du wiki.

1. Ingénieur QA :

   - Crée la page wiki `feature-x-test-plan`.
   - Lie les tickets de test #301-305 au plan de test.
   - Documente les résultats des tests dans le wiki avec des références aux tickets.

1. Rédacteur technique :

   - Met à jour la documentation utilisateur dans le wiki.
   - Crée le ticket de documentation #401.
   - Lie les modifications du wiki à l'epic de fonctionnalité.

### Exemple 2 : base de connaissances de l'équipe avec tableaux de bord en direct {#example-2-team-knowledge-base-with-live-dashboards}

Structurez le manuel de votre équipe avec des vues intégrées pour des informations en temps réel :

````markdown
# Engineering team handbook

## Current sprint status

```glql
display: table
title: Sprint Progress
fields: title, assignee, state, labels("workflow::*") as "Status"
limit: 20
query: project = "team/project" and milestone = "Sprint 23" and opened = true
```

## Processes

- [[Sprint Planning Process|sprint-planning-process]] - How we plan sprints
- [[Code Review Guidelines|code-review-guidelines]] - Review standards and SLAs
- [[Incident Response|incident-response]] - On-call procedures

## Technical standards

- [[API Design Standards|API-design-standards]] - REST API conventions
- [[Database Schema Guide|database-schema-guide]] - Schema design rules
- [[Security Checklist|security-checklist]] - Security requirements

## Work management

- [Issue board](https://gitlab.example.com/group/project/-/boards/123)
- [Current milestone](https://gitlab.example.com/group/project/-/milestones/45)
- Label taxonomy: [[Label Definitions|label-definitions]]

## Onboarding

- [[New Developer Setup|new-developer-setup]] - Environment setup
- [[First Week Issues|first-week-issues]] - Good first issues: #101, #102, #103
- [[Team Contacts|team-contacts]] - Who to ask for what
````

## Référence rapide {#quick-reference}

### Syntaxe de liaison wiki {#wiki-linking-syntax}

| Objectif                          | Syntaxe                                    | Exemple |
| -------------------------------- | ----------------------------------------- | ------- |
| Lien vers une page wiki (même projet) | `[[page-slug]]`                           | `[[api-standards]]` |
| Lien avec texte personnalisé            | `[[Display Text\|page-slug]]`             | `[[our API guide\|api-standards]]` |
| Lien wiki inter-projets          | `[[group/project:page-slug]]`             | `[[backend/api:rest-guide]]` |
| Syntaxe wiki alternative          | `[wiki_page:page-slug]`                   | `[wiki_page:home]` |
| Alternative inter-projets        | `[wiki_page:namespace/project:page-slug]` | `[wiki_page:backend/api:home]` |
| Lien hiérarchique (même niveau)   | `[Link text](page-slug)`                  | `[Related](related-page)` |
| Lien hiérarchique (parent)       | `[Link text](../parent-page)`             | `[Up](../main)` |
| Lien hiérarchique (enfant)        | `[Link text](child-page)`                 | `[Details](details)` |
| Lien racine                        | `[Link text](/page-from-root)`            | `[Home](/home)` |
| URL complète                         | Markdown standard                         | `[API Guide](https://gitlab.example.com/.../wikis/api-standards)` |

<!-- The `page-from-root` example is added as exception in `doc/.vale/gitlab_docs/InternalLinkFormat.yml` -->

### Référencer les éléments de travail {#referencing-work-items}

| Type d'élément                 | Syntaxe              | Exemple |
| ------------------------- | ------------------- | ------- |
| Ticket (même projet)      | `#123`              | `#123`  |
| Ticket (projet différent) | `group/project#123` | `gitlab-org/gitlab#123` |
| Merge request             | `!123`              | `!123`  |
| Epic                      | `&123`              | `&123`  |
| Jalon                 | `%"Milestone Name"` | `%"18.5"` |

### Créer des tickets depuis le wiki {#creating-issues-from-wiki}

Utilisez des listes de tâches dans le wiki qui peuvent être converties en tickets :

```markdown
## Action items from retrospective

- [ ] Improve CI pipeline performance
- [ ] Update documentation
- [ ] Add monitoring for API endpoints
```

Cochez les cases et utilisez **Créer un ticket** pour convertir les tâches en tickets suivis.

## Conseils pour une intégration efficace {#tips-for-effective-integration}

### Utiliser correctement les slugs de page {#use-page-slugs-correctly}

- Les liens wiki utilisent des slugs de page (versions adaptées aux URL) : `api-standards` et non `API Standards`.
- Lorsqu'une page n'existe pas, sélectionner le lien vous permet de la créer.
- Les URL wiki collées sont automatiquement converties en texte lisible (les tirets deviennent des espaces).

### Maintenir des liens bidirectionnels {#maintain-bidirectional-links}

- Lorsque vous créez un lien du wiki vers un ticket, mettez également à jour le ticket pour qu'il référence la page wiki.
- Utilisez des conventions de nommage cohérentes pour faciliter la découverte.
- Envisagez d'automatiser la création de liens à l'aide de webhooks ou de CI/CD.

### Organiser pour la découverte {#organize-for-discovery}

- Créez une page d'accueil wiki qui indexe toute la documentation de planification.
- Utilisez un nommage de page cohérent : `sprint-2025-01`, `adr-001`, `feature-name`.
- Utilisez une structure hiérarchique avec des dossiers pour les wikis volumineux.
- Étiquetez les pages wiki avec des catégories correspondant à votre taxonomie de labels.

### Maintenir la documentation à jour {#keep-documentation-current}

- Incluez les mises à jour de documentation dans votre Définition de Terminé.
- Révisez les pages wiki lors de la planification du sprint.
- Archivez les pages obsolètes dans un dossier `archive/`.

### Utiliser des modèles {#use-templates}

Créez des modèles wiki pour les documents courants :

- Modèle de planification de sprint
- Modèle de rétrospective
- Modèle de spécification de fonctionnalité
- Modèle de registre de décisions d'architecture

## Sujets connexes {#related-topics}

- [Wiki](_index.md)
- [Les tickets](../issues/_index.md)
- [Tableaux des tickets](../issue_board.md)
- [Les epics](../../group/epics/_index.md)
- [GitLab Query Language](../../glql/_index.md)
- [Markdown GitLab Flavored](../../markdown.md)
