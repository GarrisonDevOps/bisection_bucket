---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Badges
description: "Statut du pipeline, badges numériques de groupe, de projet et personnalisés."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les badges numériques constituent un moyen unifié de présenter des informations condensées sur vos projets. Un badge numérique se compose d'une petite image et d'une URL vers laquelle l'image pointe. Dans GitLab, les badges numériques sont affichés sur la page de présentation du projet, sous la description du projet. Vous pouvez utiliser des badges numériques au niveau du [projet](#project-badges) et du [groupe](#group-badges).

## Badges numériques disponibles {#available-badges}

GitLab fournit les badges numériques de pipeline suivants :

- [Badges numériques de statut de pipeline](#pipeline-status-badges)
- [Badges numériques de rapport de couverture de test](#test-coverage-report-badges)
- [Badges numériques de dernière release](#latest-release-badges)

GitLab prend également en charge [l'ajustement du style des badges numériques](#customize-badges).

## Badges numériques de statut de pipeline {#pipeline-status-badges}

Le badge numérique de statut de pipeline indique le statut du dernier pipeline d'un projet. Selon le statut de votre pipeline, le badge numérique peut avoir l'une des valeurs suivantes :

- `pending`
- `running`
- `passed`
- `failed`
- `skipped`
- `manual`
- `canceled`
- `unknown`

Vous pouvez accéder à une image de badge numérique de statut de pipeline en utilisant le lien suivant :

```plaintext
https://gitlab.example.com/<namespace>/<project>/badges/<branch>/pipeline.svg
```

### Afficher uniquement le statut non ignoré {#display-only-non-skipped-status}

Pour que le badge numérique de statut de pipeline n'affiche que le dernier statut non ignoré, utilisez le paramètre de requête `?ignore_skipped=true` :

```plaintext
https://gitlab.example.com/<namespace>/<project>/badges/<branch>/pipeline.svg?ignore_skipped=true
```

## Badges numériques de rapport de couverture de test {#test-coverage-report-badges}

Le badge numérique de rapport de couverture de test indique le pourcentage de code testé dans un projet. La valeur est calculée sur la base du dernier pipeline réussi.

Vous pouvez accéder à une image de badge numérique de rapport de couverture de test en utilisant le lien suivant :

```plaintext
https://gitlab.example.com/<namespace>/<project>/badges/<branch>/coverage.svg
```

Vous pouvez définir l'expression régulière pour la [couverture de code](../../ci/testing/code_coverage/coverage_reporting.md#configure-coverage-reporting) à laquelle chaque job log est comparé. Cela signifie que chaque job dans le pipeline peut avoir la valeur de pourcentage de couverture de test définie.

Pour obtenir le rapport de couverture à partir d'un job spécifique, ajoutez le paramètre `job=coverage_job_name` à l'URL. Par exemple, vous pouvez utiliser un code similaire à celui qui suit pour ajouter le badge numérique de rapport de couverture de test du job `coverage` à un fichier Markdown :

```markdown
![coverage](https://gitlab.example.com/<namespace>/<project>/badges/<branch>/coverage.svg?job=coverage)
```

### Limites de couverture de test et couleurs des badges numériques {#test-coverage-limits-and-badge-colors}

Le tableau suivant présente les limites de couverture de test par défaut et les couleurs des badges numériques :

| Couverture de test | Limites en pourcentage           | Couleur du badge numérique |
|---------------|-----------------------------|-------------|
| Bonne          | De 95 % jusqu'à 100 % inclus | <span style="color: #4c1">■</span> `#4c1` |
| Acceptable    | De 90 % jusqu'à 95 %                | <span style="color:#a3c51c"> ■</span> `#a3c51c` |
| Moyen        | De 75 % jusqu'à 90 %                | <span style="color: #dfb317">■</span> `#dfb317` |
| Faible           | De 0 % jusqu'à 75 %                 | <span style="color: #e05d44">■</span> `#e05d44` |
| Inconnu       | Aucune couverture                 | <span style="color: #9f9f9f">■</span> `#9f9f9f` |

> [!note]
> _Jusqu'à_ signifie jusqu'à la borne supérieure, mais sans l'inclure.

### Modifier les limites par défaut {#change-the-default-limits}

Vous pouvez remplacer les limites par défaut en transmettant les paramètres de requête suivants dans l'URL du badge numérique de rapport de couverture :

| Paramètre de requête  | Valeurs acceptables                            | Valeur par défaut |
|------------------|----------------------------------------------|---------|
| `min_good`       | Toute valeur comprise entre `3` et `100`              | `95`    |
| `min_acceptable` | Toute valeur comprise entre `2` et `min_good`−1       | `90`    |
| `min_medium`     | Toute valeur comprise entre `1` et `min_acceptable`−1 | `75`    |

Par exemple :

```plaintext
https://gitlab.example.com/<namespace>/<project>/badges/<branch>/coverage.svg?min_good=98&min_acceptable=75
```

Si vous définissez une limite invalide, GitLab l'ajuste automatiquement pour qu'elle soit valide. Par exemple, si vous définissez `min_good` sur `80` et `min_acceptable` sur `85`, GitLab définit `min_acceptable` sur `79` (`min_good - 1`) car la valeur minimale acceptable ne peut pas être supérieure à la valeur minimale correcte.

## Badges numériques de dernière release {#latest-release-badges}

Le badge numérique de dernière release indique le nom du dernier tag de release de votre projet. S'il n'y a aucune release, il affiche `none`.

Vous pouvez accéder à une image de badge numérique de dernière release en utilisant le lien suivant :

```plaintext
https://gitlab.example.com/<namespace>/<project>/-/badges/release.svg
```

Par défaut, le badge numérique récupère la release triée en utilisant l'heure [`released_at`](../../api/releases/_index.md#create-a-release) avec le paramètre de requête `?order_by`.

```plaintext
https://gitlab.example.com/<namespace>/<project>/-/badges/release.svg?order_by=release_at
```

Vous pouvez modifier la largeur du champ de nom de release en utilisant le paramètre `value_width`. La valeur doit être comprise entre 1 et 200, et la valeur par défaut est 54. Si vous définissez une valeur hors plage, GitLab l'ajuste automatiquement à la valeur par défaut.

## Badges numériques de projet {#project-badges}

Les badges numériques peuvent être ajoutés à un projet par des Mainteneurs ou des Propriétaires, et sont visibles sur la page **Vue d'ensemble** du projet. Si vous devez ajouter les mêmes badges numériques à plusieurs projets, vous pouvez envisager de les ajouter au [niveau du groupe](#group-badges).

### Exemple de badge numérique de projet : statut du pipeline {#example-project-badge-pipeline-status}

Un badge numérique de projet courant présente le statut du pipeline GitLab CI.

Pour ajouter ce badge numérique à un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Badges numériques**.
1. Sous **Nom**, saisissez _Pipeline Status_.
1. Sous **Lien**, saisissez l'URL suivante : `https://gitlab.example.com/%{project_path}/-/commits/%{default_branch}`
1. Sous **URL de l'image du badge**, saisissez l'URL suivante : `https://gitlab.example.com/%{project_path}/badges/%{default_branch}/pipeline.svg`
1. Sélectionnez **Ajouter un badge**.

## Badges numériques de groupe {#group-badges}

Les badges numériques peuvent être ajoutés à un groupe par des Propriétaires, et sont visibles sur la page **Vue d'ensemble** de tout projet appartenant au groupe. En ajoutant un badge numérique à un groupe, vous ajoutez et appliquez un badge numérique au niveau du projet pour tous les projets du groupe.

> [!note]
> Bien que ces badges numériques apparaissent comme des badges numériques au niveau du projet dans la base de code, ils ne peuvent pas être modifiés ou supprimés au niveau du projet.

Si vous avez besoin de badges numériques individuels pour chaque projet, vous pouvez :

- Ajouter le badge numérique au [niveau du projet](#project-badges).
- Utiliser des [espaces réservés](#placeholders).

## Afficher les badges numériques {#view-badges}

Pour afficher les badges numériques disponibles dans un projet ou un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Badges numériques**.

## Ajouter un badge numérique {#add-a-badge}

Pour ajouter un nouveau badge numérique à un projet ou un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Badges numériques**.
1. Sélectionnez **Ajouter un badge**.
1. Dans la zone de texte **Nom**, saisissez le nom de votre badge numérique.
1. Dans la zone de texte **Lien**, saisissez l'URL vers laquelle les badges numériques doivent pointer.
1. Dans la zone de texte **URL de l'image du badge**, saisissez l'URL de l'image que vous souhaitez afficher pour le badge numérique.
1. Sélectionnez **Ajouter un badge**.

## Afficher l'URL des badges numériques de pipeline {#view-the-url-of-pipeline-badges}

Vous pouvez afficher le lien exact de vos badges numériques. Vous pouvez ensuite utiliser ce lien pour intégrer le badge numérique dans vos pages HTML ou Markdown.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD**.
1. Développez **Pipelines généraux**.
1. Dans les sections **Statut du pipeline**, **Rapport de couverture** ou **Dernière release**, affichez les URL des images.

> [!note]
> Le badge numérique de statut de pipeline est basé sur des révisions Git spécifiques (branches). Assurez-vous de sélectionner la branche appropriée pour afficher le statut de pipeline correct.

## Personnaliser les badges numériques {#customize-badges}

{{< details >}}

- Statut : version bêta

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/180832) dans GitLab 18.5 [avec le feature flag](../../administration/feature_flags/_index.md) `custom_project_badges`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/574344) dans GitLab 18.6.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/574344) dans GitLab 19.2. Le feature flag `custom_project_badges` a été supprimé.

{{< /history >}}

Vous pouvez personnaliser l'apparence des badges numériques dans votre projet :

- La [personnalisation de base](#basic-customization) fonctionne pour tous les types de badges numériques.
- La [personnalisation avancée](#custom-badges) est disponible uniquement pour les badges numériques personnalisés.

### Personnalisation de base {#basic-customization}

Vous pouvez personnaliser les aspects suivants de tous les types de badges numériques :

- [Style](#style)
- [Texte de la clé](#key-text)
- [Largeur de la clé](#key-width)
- [Largeur de la valeur](#value-width)

#### Style {#style}

Les badges numériques de pipeline, de couverture, de release et personnalisés peuvent être rendus dans différents styles en ajoutant le paramètre `style=style_name` à l'URL. Deux styles sont disponibles :

- Plat (par défaut) :

  ```plaintext
  https://gitlab.example.com/<namespace>/<project>/badges/<branch>/coverage.svg?style=flat
  ```

  ![Badge numérique de couverture affichant une couverture de 95,00 %.](img/badge_flat.svg)

- Carré plat :

  ```plaintext
  https://gitlab.example.com/<namespace>/<project>/badges/<branch>/coverage.svg?style=flat-square
  ```

  ![Badge numérique de couverture affichant une couverture de 95,00 % dans un style carré plat.](img/badge_flat_square.svg)

#### Texte de la clé {#key-text}

Le texte du côté gauche du badge numérique peut être personnalisé. Par exemple, pour différencier plusieurs jobs de couverture qui s'exécutent dans le même pipeline.

Personnalisez le texte de la clé du badge numérique en ajoutant le paramètre `key_text=custom_text` à l'URL :

```plaintext
https://gitlab.example.com/gitlab-org/gitlab/badges/main/coverage.svg?job=karma&key_text=Frontend+Coverage&key_width=130
```

![Badge numérique Frontend Coverage affichant une couverture de 95,00 %.](img/badge_custom_text.svg)

#### Largeur de la clé {#key-width}

Personnalisez la largeur de la clé du badge numérique en ajoutant le paramètre `key_width=width` à l'URL :

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/coverage.svg?key_width=130
```

#### Largeur de la valeur {#value-width}

Personnalisez la largeur de la valeur du badge numérique en ajoutant le paramètre `value_width=width` à l'URL :

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/coverage.svg?value_width=130
```

### Badges numériques personnalisés {#custom-badges}

Les badges numériques personnalisés vous donnent un contrôle total sur les deux côtés du badge numérique. Contrairement aux badges numériques standard qui affichent des informations prédéfinies (comme le statut du pipeline), les badges numériques personnalisés vous permettent de :

- Afficher n'importe quel texte de chaque côté du badge numérique
- Utiliser des couleurs personnalisées
- Afficher des informations spécifiques au projet
- Créer des badges numériques dynamiques en utilisant des [espaces réservés](#placeholders)

En plus des [options de personnalisation de base](#basic-customization), les badges numériques personnalisés prennent en charge ces options de personnalisation supplémentaires :

- [Couleur de la clé](#key-color)
- [Couleur de la valeur](#value-color)
- [Texte de la valeur](#value-text)

Vous pouvez ajouter un badge numérique personnalisé en utilisant le lien suivant :

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/custom.svg
```

Par exemple, vous pouvez utiliser des [espaces réservés](#placeholders) pour créer un badge numérique pour le dernier tag :

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/custom.svg?key_text=Latest_tag&value_text=%{latest_tag}&key_color=white&value_color=7bc043
```

> [!warning]
> Les espaces réservés permettent aux badges numériques d'exposer des informations autrement privées, telles que la branche par défaut ou le SHA du commit lorsque le projet est configuré avec un dépôt privé. Ce comportement est intentionnel, car les badges numériques sont destinés à être utilisés publiquement. Évitez d'utiliser ces espaces réservés si les informations sont sensibles.

#### Texte de la valeur {#value-text}

Personnalisez le texte affiché sur le côté droit en ajoutant le paramètre `value_text=text` à l'URL :

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/custom.svg?value_text=badge
```

#### Couleur de la valeur {#value-color}

Personnalisez la couleur d'arrière-plan du côté droit en ajoutant le paramètre `value_color=color` à l'URL :

Les couleurs peuvent être transmises sous forme de :

- [Une couleur nommée](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Values/named-color), par exemple `blue`
- Représentation hexadécimale telle que `fff` ou `7bc043` (sans le `#` initial)

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/custom.svg?value_color=red
```

#### Couleur de la clé {#key-color}

Personnalisez la couleur d'arrière-plan du côté gauche en ajoutant le paramètre `value_color=color` à l'URL :

Les couleurs peuvent être transmises sous forme de :

- [Une couleur nommée](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Values/named-color), par exemple `blue`
- Représentation hexadécimale telle que `fff` ou `7bc043` (sans le `#` initial)

```plaintext
https://gitlab.example.com/%{project_path}/-/badges/custom.svg?key_color=green
```

### Ajouter une image de badge numérique personnalisée {#add-a-custom-badge-image}

Prérequis :

- Vous devez disposer du rôle Développeur, Mainteneur ou Propriétaire pour le projet ou le groupe.
- Vous devez disposer d'une URL valide pointant directement vers l'image souhaitée pour le badge numérique. Si l'image se trouve dans un dépôt GitLab, utilisez le lien brut vers l'image.

Pour ajouter un badge numérique personnalisé avec une image :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Badges numériques**.
1. Sous **Nom**, saisissez le nom du badge numérique.
1. Sous **Lien**, saisissez l'URL vers laquelle le badge numérique doit pointer.
1. Sous **URL de l'image du badge**, saisissez l'URL de votre image personnalisée. Par exemple, pour utiliser une image de votre dépôt :

   ```plaintext
   https://gitlab.example.com/<project_path>/-/raw/<default_branch>/custom-image.svg
   ```

1. Sélectionnez **Ajouter un badge**.

Pour utiliser des images personnalisées générées par un pipeline, consultez [l'accès aux derniers artefacts de job par URL](../../ci/jobs/job_artifacts.md#by-job-name-and-branch).

## Modifier un badge numérique {#edit-a-badge}

Pour modifier un badge numérique dans un projet ou un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Badges numériques**.
1. À côté du badge numérique que vous souhaitez modifier, sélectionnez **Modifier** ({{< icon name="pencil" >}}).
1. Modifiez le **Nom**, le **Lien** ou l'**URL de l'image du badge**.
1. Sélectionnez **Enregistrer les modifications**.

## Supprimer un badge numérique {#delete-a-badge}

Pour supprimer un badge numérique dans un projet ou un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Badges numériques**.
1. À côté du badge numérique que vous souhaitez supprimer, sélectionnez **Supprimer** ({{< icon name="remove" >}}).
1. Dans la boîte de dialogue de confirmation, sélectionnez **Supprimer le badge**.

> [!note]
> Les badges numériques associés à un groupe ne peuvent être modifiés ou supprimés qu'au [niveau du groupe](#group-badges).

## Espaces réservés {#placeholders}

L'URL vers laquelle pointe un badge numérique et l'URL de l'image peuvent contenir des espaces réservés, qui sont évalués lors de l'affichage du badge numérique. Les espaces réservés suivants sont disponibles :

- `%{project_path}` : Chemin d'un projet incluant les groupes parents
- `%{project_title}` : Titre d'un projet
- `%{project_name}` : Nom d'un projet
- `%{project_id}` : ID de base de données associé à un projet
- `%{project_namespace}` : Espace de nommage de projet d'un projet
- `%{group_name}` : Groupe d'un projet
- `%{gitlab_server}` : Serveur d'un projet
- `%{gitlab_pages_domain}` : Domaine hébergeant GitLab Pages
- `%{default_branch}` : Nom de la branche par défaut configurée pour le dépôt d'un projet
- `%{commit_sha}` : ID du commit le plus récent sur la branche par défaut du dépôt d'un projet
- `%{latest_tag}` : Dernier tag ajouté au dépôt du projet

> [!warning]
> Les espaces réservés permettent aux badges numériques d'exposer des informations autrement privées, telles que la branche par défaut ou le SHA du commit lorsque le projet est configuré avec un dépôt privé. Ce comportement est intentionnel, car les badges numériques sont destinés à être utilisés publiquement. Évitez d'utiliser ces espaces réservés si les informations sont sensibles.

<!-- -->

> [!warning]
> En raison du [ticket 481729](https://gitlab.com/gitlab-org/gitlab/-/work_items/481729), `%{gitlab_server}` et `%{gitlab_pages_domain}` ne peuvent pas être utilisés pour spécifier le nom d'hôte dans l'URL, mais uniquement pour d'autres paramètres.
