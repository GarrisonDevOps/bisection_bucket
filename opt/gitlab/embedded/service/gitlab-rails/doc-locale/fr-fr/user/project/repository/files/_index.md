---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Recherchez des fichiers dans votre dépôt GitLab directement depuis l'interface utilisateur de GitLab."
title: Gestion des fichiers
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'interface utilisateur de GitLab étend les capacités d'historique et de suivi de Git avec des fonctionnalités conviviales dans votre navigateur. Vous pouvez :

- Rechercher des fichiers.
- Modifier la gestion des fichiers.
- Explorer l'historique d'un fichier entier ou d'une seule ligne.

## Comprendre comment les types de fichiers s'affichent dans l'interface utilisateur {#understand-how-file-types-render-in-the-ui}

Lorsque vous ajoutez des fichiers de ces types à votre projet, GitLab affiche leur rendu pour améliorer la lisibilité :

- Les fichiers [GeoJSON](geojson.md) s'affichent sous forme de cartes.
- Les fichiers [Jupyter Notebook](jupyter_notebooks/_index.md) s'affichent en HTML rendu.
- Les fichiers dans de nombreux langages de balisage sont rendus pour l'affichage.

### Langages de balisage pris en charge {#supported-markup-languages}

Si votre fichier possède l'une de ces extensions, GitLab affiche le contenu du [langage de balisage](https://en.wikipedia.org/wiki/Lightweight_markup_language) du fichier dans l'interface utilisateur.

| Langage de balisage                                              | Extensions |
|--------------------------------------------------------------|------------|
| Texte brut                                                   | `txt`      |
| [Markdown](../../../markdown.md)                             | `mdown`, `mkd`, `mkdn`, `md`, `markdown`, `rmd` |
| [reStructuredText](https://docutils.sourceforge.io/rst.html) | `rst`      |
| [AsciiDoc](../../../asciidoc.md)                             | `adoc`, `ad`, `asciidoc` |
| [Textile](https://textile-lang.com/)                         | `textile`  |
| [Rdoc](https://rdoc.sourceforge.net/doc/index.html)          | `rdoc`     |
| [Org mode](../../../org_mode.md)                             | `org`      |
| [creole](http://www.wikicreole.org/)                         | `creole`   |
| [MediaWiki](https://www.mediawiki.org/wiki/MediaWiki)        | `wiki`, `mediawiki` |

### Formats de diagrammes pris en charge {#supported-diagram-formats}

Si votre fichier possède l'une de ces extensions, GitLab affiche le contenu du fichier sous forme de diagramme dans l'interface utilisateur :

| Format de diagramme                                  | Extensions                                                              | Disponibilité |
|-------------------------------------------------|-------------------------------------------------------------------------|--------------|
| [Mermaid](https://mermaid.js.org/)[^mermaid-diagrams-mermaid] | `mermaid`                                                               | Toujours disponible. |
| [PlantUML](https://plantuml.com/)[^both-plantuml-kroki]  | `plantuml`, `pu`, `puml`, `iuml`                                        | Nécessite qu'un administrateur [active l'intégration PlantUML](../../../../administration/integration/plantuml.md). |
| [Kroki](https://kroki.io/)[^both-plantuml-kroki]         | `d2`, `dot`, `gv`, `noml`, `plantuml`, `pu`, `puml`, `iuml`, `vg`, `vl` | Nécessite qu'un administrateur [active l'intégration Kroki](../../../../administration/integration/kroki.md). |

[^mermaid-diagrams-mermaid]: pour les diagrammes Mermaid, seule l'extension `mermaid` est rendue. L'extension `mmd` n'est pas prise en charge. [^both-plantuml-kroki]: si les intégrations PlantUML et Kroki sont toutes deux activées, GitLab utilise PlantUML pour rendre les fichiers avec les extensions `plantuml`, `pu`, `puml` et `iuml`.

Pour en savoir plus sur la syntaxe des diagrammes, consultez [les diagrammes en Markdown](../../../markdown.md#diagrams-and-flowcharts) et [les diagrammes en AsciiDoc](../../../asciidoc.md#diagrams-and-flowcharts).

### Fichiers README et index {#readme-and-index-files}

{{< history >}}

- La prise en charge des fichiers `_index.md` a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/206533) dans GitLab 18.5.

{{< /history >}}

Lorsqu'un fichier `README`, `index` ou `_index` est présent dans un dépôt, GitLab affiche son contenu. Ces fichiers peuvent être en texte brut ou avoir l'extension d'un langage de balisage pris en charge.

L'ordre de priorité pour le rendu automatique est le suivant :

- Fichiers prévisualisables : `README.md`, `index.md`, `_index.md`, etc.
- Fichiers texte brut : `README`, `index`, `_index`, etc.

Le premier fichier trouvé dans chaque catégorie (par ordre alphabétique) est sélectionné, les fichiers prévisualisables ayant la priorité sur les fichiers texte brut. Par exemple, si plusieurs fichiers README sont disponibles, GitLab les affiche dans l'ordre suivant :

1. `README.adoc`
1. `README.md`
1. `README.rst`
1. `README`

### Afficher les fichiers OpenAPI {#render-openapi-files}

GitLab affiche les fichiers de spécification OpenAPI si le nom de fichier contient `openapi` ou `swagger`, et si l'extension est `yaml`, `yml` ou `json`. Ces exemples sont tous corrects :

- `openapi.yml`, `openapi.yaml`, `openapi.json`
- `swagger.yml`, `swagger.yaml`, `swagger.json`
- `OpenAPI.YML`, `openapi.Yaml`, `openapi.JSON`
- `openapi_gitlab.yml`, `openapi.gitlab.yml`
- `gitlab_swagger.yml`
- `gitlab.openapi.yml`

Pour afficher un fichier OpenAPI :

1. [Recherchez](#search-for-a-file) le fichier OpenAPI dans votre dépôt.
1. Sélectionnez **Afficher le rendu du fichier**.
1. Pour afficher `operationId` dans la liste des opérations, ajoutez `displayOperationId=true` à la chaîne de requête.

> [!note]
> Lorsque `displayOperationId` est présent dans la chaîne de requête et a une valeur quelconque, il est évalué à `true`. Ce comportement correspond au comportement par défaut de Swagger.

## Imprimer un fichier Markdown au format PDF {#print-a-markdown-file-as-pdf}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/414692) dans GitLab 19.1 [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `blob_markdown_pdf_download`. Désactivé par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Imprimez un fichier Markdown au format PDF pour enregistrer son contenu rendu en vue de le partager ou de l'archiver. Lorsque vous affichez un fichier Markdown, l'action **Téléchargement** est une liste déroulante avec deux options : **Télécharger au format Markdown** et **Imprimer en PDF**.

Pour imprimer un fichier Markdown au format PDF :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez au fichier Markdown que vous souhaitez imprimer.
1. En haut à droite, sélectionnez **Téléchargement** ({{< icon name="download" >}}) > **Imprimer en PDF**.
1. Dans la boîte de dialogue d'impression de votre navigateur, enregistrez le fichier au format PDF.

## Afficher les enregistrements Git d'un fichier {#view-git-records-for-a-file}

Les informations historiques sur les fichiers de votre dépôt sont disponibles dans l'interface utilisateur de GitLab :

- [Historique de fichier Git](git_history.md) : affiche l'historique des commits d'un fichier entier.
- [Git blame](git_blame.md) : affiche chaque ligne d'un fichier texte, ainsi que le commit le plus récent ayant modifié cette ligne.

## Créer des permaliens {#create-permalinks}

Les permaliens sont des URL permanentes qui pointent vers des fichiers, des répertoires ou des sections de code spécifiques dans votre dépôt. Ils restent valides même lorsque le dépôt évolue, ce qui les rend idéaux pour partager et référencer du code dans la documentation, les tickets ou les merge requests.

Pour créer un permalien :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez au fichier ou au répertoire vers lequel vous souhaitez créer un lien.
1. Facultatif. Pour des sélections de code spécifiques :
   - **Ligne unique** : sélectionnez le numéro de ligne.
   - **Plusieurs lignes** : sélectionnez le premier numéro de ligne, puis maintenez <kbd>Shift</kbd> enfoncé et sélectionnez le dernier numéro de ligne.
   - **Ancre Markdown** : survolez un titre pour afficher le lien d'ancre ({{< icon name="link" >}}), puis sélectionnez-le.
1. Sélectionnez **Actions** ({{< icon name="ellipsis_v" >}}), puis sélectionnez **Copier le permalien**. Vous pouvez également appuyer sur <kbd>y</kbd>. Pour plus de raccourcis, consultez [les raccourcis clavier](../../../shortcuts.md).

Lorsque vous collez un permalien vers des lignes d'un fichier dans un commentaire ou une description, GitLab peut [intégrer le code](../../../markdown.md#embed-code-from-a-repository) à la place du lien.

## Afficher les merge requests ouvertes pour un fichier {#view-open-merge-requests-for-a-file}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/448868) dans GitLab 17.10 [avec le feature flag](../../../../administration/feature_flags/_index.md) `filter_blob_path`.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/505449) dans GitLab 17.11.
- [Activé sur GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/505449) dans GitLab 18.0.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/539215) dans GitLab 18.2. Le feature flag `filter_blob_path` a été supprimé.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Lors de l'affichage d'un fichier du dépôt, GitLab affiche un badge indiquant le nombre de merge requests ouvertes qui ciblent la branche actuelle et modifient le fichier. Cela vous aide à identifier les fichiers qui ont des modifications en attente.

Pour afficher les merge requests ouvertes pour un fichier :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez au fichier que vous souhaitez afficher.
1. En haut à droite de l'écran, à côté du nom du fichier, recherchez le badge vert indiquant le nombre de {{< icon name="merge-request-open" >}} merge requests **Ouvrir**.
1. Sélectionnez le badge pour afficher la liste des merge requests ouvertes créées au cours des 30 derniers jours.
1. Sélectionnez n'importe quelle merge request dans la liste pour accéder à cette merge request.

## Rechercher un fichier {#search-for-a-file}

Utilisez le sélecteur de fichiers pour rechercher directement depuis l'interface utilisateur de GitLab un fichier dans votre dépôt. Le sélecteur de fichiers utilise la recherche approximative et met en évidence les résultats au fur et à mesure que vous tapez.

Pour rechercher un fichier, appuyez sur <kbd>t</kbd> n'importe où dans votre projet, ou :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Dépôt**.
1. En haut à droite, sélectionnez **Rechercher un fichier**.
1. Dans la boîte de dialogue, commencez à saisir le nom du fichier :

   ![Bouton Rechercher un fichier](img/file_finder_v17_2.png)

1. Facultatif. Pour affiner les options de recherche, appuyez sur <kbd>Command</kbd>+<kbd>K</kbd> ou sélectionnez **Commandes** dans le coin inférieur droit de la boîte de dialogue :
   - Pour **Pages ou actions**, saisissez <kbd>></kbd>.
   - Pour **Utilisateurs**, saisissez <kbd>@</kbd>.
   - Pour **Projets**, saisissez <kbd>:</kbd>.
   - Pour **Fichiers**, saisissez <kbd>~</kbd>.
1. Dans la liste déroulante, sélectionnez le fichier pour l'afficher dans votre dépôt.

Pour revenir à la page **Fichiers**, appuyez sur <kbd>Esc</kbd>.

Cette fonctionnalité utilise la bibliothèque [`fuzzaldrin-plus`](https://github.com/jeancroy/fuzz-aldrin-plus).

## Modifier la façon dont Git gère un fichier {#change-how-git-handles-a-file}

Pour modifier la gestion par défaut d'un fichier ou d'un type de fichier, créez un [fichier `.gitattributes`](git_attributes.md). Utilisez les fichiers `.gitattributes` pour :

- Configurer l'affichage des fichiers dans les diffs, par exemple la [coloration syntaxique](highlighting.md) ou le [repli des fichiers générés](../../merge_requests/changes.md#collapse-generated-files).
- Contrôler le stockage et la protection des fichiers, par exemple en [rendant les fichiers en lecture seule](../../file_lock.md), ou en stockant les fichiers volumineux [avec Git LFS](../../../../topics/git/lfs/_index.md).

## Sujets connexes {#related-topics}

- [API des fichiers de dépôt](../../../../api/repository_files.md)
- [Gestion des fichiers avec Git](../../../../topics/git/file_management.md)

## Dépannage {#troubleshooting}

### Langages du dépôt : utilisation excessive du CPU {#repository-languages-excessive-cpu-use}

Pour déterminer quels langages sont utilisés dans les fichiers d'un dépôt, GitLab utilise un gem Ruby. Lorsque le gem analyse un fichier pour déterminer son type, [le processus peut consommer excessivement le CPU](https://gitlab.com/gitlab-org/gitaly/-/issues/1565). Le gem contient un [fichier de configuration heuristique](https://github.com/github-linguist/linguist/blob/main/lib/linguist/heuristics.yml) qui définit les extensions de fichiers à analyser. Ces types de fichiers peuvent consommer excessivement le CPU :

- Les fichiers avec l'extension `.txt`.
- Les fichiers XML avec une extension non définie par le gem.

Pour résoudre ce problème, modifiez votre fichier `.gitattributes` et assignez un langage à des extensions de fichiers spécifiques. Vous pouvez également utiliser cette approche pour corriger les types de fichiers mal identifiés :

1. Identifiez le langage à spécifier. Le gem contient un [fichier de configuration pour les types de données connus](https://github.com/github-linguist/linguist/blob/main/lib/linguist/languages.yml).

1. Pour ajouter une entrée pour les fichiers texte, par exemple :

   ```yaml
   Text:
     type: prose
     wrap: true
     aliases:
     - fundamental
     - plain text
     extensions:
     - ".txt"
   ```

1. Ajoutez ou modifiez `.gitattributes` à la racine de votre dépôt :

   ```plaintext
   *.txt linguist-language=Text
   ```

   Les fichiers `*.txt` ont une entrée dans le fichier heuristique. Cet exemple empêche l'analyse de ces fichiers.
