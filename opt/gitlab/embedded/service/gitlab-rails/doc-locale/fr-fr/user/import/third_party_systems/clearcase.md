---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Migrer depuis IBM DevOps ClearCase
description: "Migrer d'IBM DevOps ClearCase vers Git."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[IBM DevOps ClearCase](https://www.ibm.com/products/devops-code-clearcase) est un ensemble d'outils développé par IBM qui inclut également un système de contrôle de version centralisé similaire à Git.

Le tableau suivant illustre les principales différences entre ClearCase et Git :

| Fonctionnalité           | ClearCase                    | Git |
|:------------------|:-----------------------------|:----|
| Modèle de dépôt  | Client-serveur                | Distribué |
| ID de révision      | Branche + numéro              | ID alphanumérique global |
| Portée de la modification   | Fichier                         | Instantané de l'arborescence de répertoires |
| Modèle de simultanéité | Fusion                        | Fusion |
| Méthode de stockage    | Deltas                       | Contenu complet |
| Client            | interface de ligne de commande, Eclipse, CC Client      | interface de ligne de commande, Eclipse, client Git/interfaces graphiques |
| Serveur            | UNIX, systèmes Windows hérités | UNIX, macOS |
| Licence           | Propriétaire                  | GPL |

## Migrer vers Git {#migrate-to-git}

Nous ne fournissons pas d'outil pour migrer d'IBM DevOps ClearCase vers Git. Pour obtenir des informations sur la migration, consultez ces ressources :

- [Bridge for Git and ClearCase](https://github.com/charleso/git-cc)
- [ClearCase vers Git](https://therub.org/2013/07/19/clearcase-to-git/)
- [Synchronisation bidirectionnelle de ClearCase vers Git](https://therub.org/2013/10/22/dual-syncing-clearcase-and-git/)
- [Passer à Git depuis ClearCase](https://sateeshkumarb.wordpress.com/2011/01/15/moving-to-git-from-clearcase/)
