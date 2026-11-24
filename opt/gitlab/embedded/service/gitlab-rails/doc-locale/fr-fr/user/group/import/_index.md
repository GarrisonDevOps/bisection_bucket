---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Migrer des données GitLab par transfert direct
description: "Utiliser une connexion directe pour migrer des données GitLab."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez migrer des groupes GitLab :

- De GitLab Self-Managed et GitLab Dedicated vers GitLab.com
- De GitLab.com vers GitLab Self-Managed et GitLab Dedicated
- D'une instance GitLab Self-Managed ou GitLab Dedicated vers une autre
- Sur la même instance GitLab

La migration par transfert direct crée une nouvelle copie du groupe. Si vous souhaitez déplacer des groupes plutôt que de les copier, vous pouvez [transférer des groupes](../manage.md#transfer-a-group) si ceux-ci se trouvent dans la même instance GitLab. Le transfert de groupes plutôt que leur migration est une option plus rapide et plus complète.

Vous pouvez migrer des groupes de plusieurs façons :

- Par transfert direct (recommandé).
- Par [transfert hors ligne](../../import/gitlab_instances/offline-transfer-migrations.md) via le stockage d'objets, lorsque l'instance de destination ne dispose pas de connexion réseau directe vers l'instance source.
- En [important un fichier d'export](../../project/settings/import_export.md).

Si vous migrez de GitLab.com vers une instance GitLab Self-Managed ou GitLab Dedicated, un administrateur peut créer des utilisateurs sur l'instance.

Sur GitLab Self-Managed et GitLab Dedicated, la [migration des éléments de groupe](migrated_items.md#migrated-group-items) n'est pas disponible par défaut. Pour activer la fonctionnalité, un administrateur peut [l'activer dans les paramètres de l'application](../../../administration/settings/import_and_export_settings.md#enable-migration-of-groups-and-projects-by-direct-transfer).

La migration des groupes par transfert direct copie les groupes d'un emplacement vers un autre. Vous pouvez :

- Copier plusieurs groupes à la fois.
- Dans l'interface GitLab, copier des groupes principaux vers :
  - Un autre groupe principal.
  - Le sous-groupe d'un groupe principal existant.
  - Une autre instance GitLab, y compris GitLab.com.
- Dans l'[API de migration de groupes et de projets par transfert direct](../../../api/bulk_imports.md), copier des groupes principaux et des sous-groupes vers ces emplacements.
- Copier des groupes avec ou sans projets. La copie de groupes avec des projets est disponible par défaut sur GitLab.com.

Toutes les ressources des groupes et des projets ne sont pas copiées. Consultez la liste des ressources copiées ci-dessous :

- [Éléments de groupe migrés](migrated_items.md#migrated-group-items).
- [Éléments de projet migrés](migrated_items.md#migrated-project-items).

Après avoir démarré une migration, vous ne devez apporter aucune modification aux groupes ou projets importés sur l'instance source, car ces modifications pourraient ne pas être copiées vers l'instance de destination.

Nous vous encourageons à laisser vos commentaires sur la migration par transfert direct dans [le ticket de retours](https://gitlab.com/gitlab-org/gitlab/-/issues/284495).

## Migration de projets spécifiques {#migrating-specific-projects}

La migration de groupes par transfert direct dans l'interface GitLab migre tous les projets du groupe. Si vous souhaitez migrer uniquement des projets spécifiques du groupe par transfert direct, vous devez utiliser l'[API](../../../api/bulk_imports.md#start-a-group-or-project-migration).

## Problèmes connus {#known-issues}

- En raison du [ticket 406685](https://gitlab.com/gitlab-org/gitlab/-/issues/406685), les fichiers dont le nom dépasse 255 caractères ne sont pas migrés.
- Lors du mappage depuis l'instance source, les membres partagés sont mappés comme membres directs sur la destination, sauf si ces appartenances existent déjà sur la destination. Cela signifie que l'importation d'un groupe principal de l'instance source vers un groupe principal de l'instance de destination mappe toujours vers des membres directs dans les projets, même si le groupe principal source contient les détails nécessaires de la hiérarchie d'appartenance partagée. La prise en charge du mappage complet des appartenances partagées est proposée dans le [ticket 458345](https://gitlab.com/gitlab-org/gitlab/-/issues/458345).
- Dans GitLab 17.0, 17.1 et 17.2, les epics et les éléments de travail importés sont mappés à l'utilisateur qui effectue l'importation plutôt qu'à l'auteur d'origine.
- Le transfert direct ne prend pas en charge la consolidation de groupes ou de projets provenant de différents groupes sources dans un groupe de destination unique. Pour consolider des groupes ou des projets, restructurez l'instance source avant la migration ou restructurez l'instance de destination [une fois la réaffectation des utilisateurs temporaires terminée](../../import/mapping/reassignment.md#completing-the-reassignment). Consultez le [ticket 589460](https://gitlab.com/gitlab-org/gitlab/-/work_items/589460).
- Si l'espace de nommage de destination appartient à une organisation différente de celle de la source, et que l'une ou l'autre organisation est marquée comme isolée, les migrations par transfert direct échouent. Pour plus d'informations, consultez le [ticket 595674](https://gitlab.com/gitlab-org/gitlab/-/issues/595674).
- Étant donné que les migrations par transfert direct associent les contributions aux utilisateurs non bannis sur l'instance de destination, les contributions des utilisateurs bannis qui étaient masquées sur l'instance source réapparaissent sur l'instance de destination. Pour masquer ces contributions, sur l'instance de destination, effectuez l'une des actions suivantes :
  - Bannir les utilisateurs.
  - Supprimer les contributions. Pour plus d'informations, consultez le [ticket 508111](https://gitlab.com/gitlab-org/gitlab/-/work_items/508111).
- Lors de la migration, les références d'URL dans les notes, les descriptions de tickets et les descriptions de merge requests ne sont réécrites que pour les liens appartenant au groupe ou au projet en cours de migration (`source_full_path`). Les URL pointant vers d'autres groupes ou projets sur l'instance source ne sont pas réécrites, même si ces groupes ou projets sont également migrés. Après la migration, vous pouvez mettre à jour manuellement tout lien externe pointant encore vers l'instance source.

## Estimation de la durée de migration {#estimating-migration-duration}

L'estimation de la durée d'une migration par transfert direct est difficile. Les facteurs suivants influent sur la durée de la migration :

- Les ressources matérielles et de base de données disponibles sur les instances GitLab source et de destination. Des ressources supplémentaires sur les instances source et de destination peuvent réduire la durée de migration, car :
  - L'instance source reçoit les requêtes API, extrait et sérialise les entités à exporter.
  - L'instance de destination exécute les jobs et crée les entités dans sa base de données.
- La complexité et la taille des données à exporter. Par exemple, imaginez que vous souhaitez migrer deux projets différents comportant chacun 1 000 merge requests. Les deux projets peuvent nécessiter des durées de migration très différentes si l'un d'eux comporte beaucoup plus de pièces jointes, de commentaires et d'autres éléments sur les merge requests. Par conséquent, le nombre de merge requests dans un projet est un mauvais indicateur de la durée de migration de ce projet.

Il n'existe pas de formule exacte pour estimer de façon fiable une migration. Cependant, la durée moyenne de chaque worker de pipeline important une {{< glossary-tooltip text="relation" >}} de projet peut vous aider à estimer la durée d'importation de vos projets.

Dans ce contexte, une relation est un type d'élément exportable.

| Type de ressource de projet       | Durée moyenne (en secondes) pour importer un enregistrement |
|:----------------------------|:---------------------------------------------|
| Projet vide               | 2.4                                          |
| Dépôt                  | 20                                           |
| Attributs du projet          | 1.5                                          |
| Membres                     | 0.2                                          |
| Labels                      | 0.1                                          |
| Les jalons                  | 0.07                                         |
| Badges                      | 0.1                                          |
| Les tickets                      | 0.1                                          |
| les snippets ;                    | 0.05                                         |
| Dépôts de snippets        | 0.5                                          |
| Tableaux                      | 0.1                                          |
| Merge Requests              | 1                                            |
| Demandes de tirage externes      | 0.5                                          |
| Branches protégées          | 0.1                                          |
| Fonctionnalité du projet             | 0.3                                          |
| Politique d'expiration des conteneurs | 0.3                                          |
| Paramètre Service Desk        | 0.3                                          |
| Les releases                    | 0.1                                          |
| Pipelines CI                | 0.2                                          |
| Notes de commit                | 0.05                                         |
| Wiki                        | 10                                           |
| les importations ;                     | 0.5                                          |
| Objets LFS                 | 0.5                                          |
| Design                      | 0.1                                          |
| Fonctionnalité Auto DevOps                 | 0.1                                          |
| Planifications de pipeline          | 0.5                                          |
| Références                  | 5                                            |
| Règle de push                   | 0.1                                          |

Bien qu'il soit difficile de prévoir la durée d'une migration, les observations suivantes ont été faites :

- 100 projets (19 900 tickets, 83 000 merge requests, 100 000+ pipelines) migrés en 8 heures.
- 1 926 projets (22 000 tickets, 160 000 merge requests, 1,1 million de pipelines) migrés en 34 heures.

Si vous migrez de grands projets et rencontrez des problèmes d'expiration de délai ou de durée de migration, essayez de [réduire la durée de migration](troubleshooting.md#migrations-are-slow-or-timing-out).

## Limites {#limits}

Pour les limites par défaut, consultez les [limites de migration par transfert direct](../../../administration/instance_limits.md#direct-transfer-migration).

Vous pouvez tester la limite de taille maximale des relations en utilisant ces API :

- [API d'export des relations de groupe](../../../api/group_relations_export.md).
- [API d'export des relations de projet](../../../api/project_relations_export.md)

Si l'une ou l'autre des API produit des fichiers dépassant la limite de taille maximale des relations, la migration de groupe par transfert direct échoue.

## Règles de visibilité {#visibility-rules}

Après la migration :

- Les groupes et projets privés restent privés.
- Les groupes et projets internes :
  - Restent internes lors de la copie dans un groupe interne, sauf si la visibilité interne est [restreinte](../../../administration/settings/visibility_and_access_controls.md#restrict-visibility-levels). Dans ce cas, les groupes et projets deviennent privés. Dans ce cas, les groupes et projets deviennent privés.
  - Deviennent privés lors de la copie dans un groupe privé.
- Les groupes et projets publics :
  - Restent publics lors de la copie dans un groupe public, sauf si la visibilité publique est [restreinte](../../../administration/settings/visibility_and_access_controls.md#restrict-visibility-levels). Dans ce cas, les groupes et projets deviennent internes. Dans ce cas, les groupes et projets deviennent internes.
  - Deviennent internes lors de la copie dans un groupe interne, sauf si la visibilité interne est [restreinte](../../../administration/settings/visibility_and_access_controls.md#restrict-visibility-levels). Dans ce cas, les groupes et projets deviennent privés. Dans ce cas, les groupes et projets deviennent privés.
  - Deviennent privés lors de la copie dans un groupe privé.

Si vous avez utilisé un réseau privé sur votre instance source pour masquer le contenu au grand public, assurez-vous de disposer d'une configuration similaire sur l'instance de destination, ou d'importer dans un groupe privé.

## Processus de migration par transfert direct {#migration-by-direct-transfer-process}

Consultez [Migrer des groupes et des projets par transfert direct](direct_transfer_migrations.md).
