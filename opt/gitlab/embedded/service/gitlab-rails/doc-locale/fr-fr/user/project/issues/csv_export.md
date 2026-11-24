---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Exporter les tickets vers un fichier CSV
description: "Exportez les tickets vers un fichier CSV qui vous est envoyé par e-mail pour une analyse hors ligne, la création de rapports ou l'importation dans d'autres systèmes."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Les colonnes `IID`, `Type`, `Start Date` et `Parent IID` ont été [ajoutées](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/199945) dans GitLab 18.4.

{{< /history >}}

Vous pouvez exporter les tickets de GitLab vers un fichier CSV ([valeurs séparées par des virgules](https://en.wikipedia.org/wiki/Comma-separated_values)) en texte brut. Le fichier CSV est joint à un e-mail et envoyé à votre adresse e-mail de notification par défaut.

<!-- vale gitlab_base.Spelling = NO -->

Les fichiers CSV peuvent être utilisés avec n'importe quel programme graphique ou tableur, comme Microsoft Excel, OpenOffice Calc ou Google Sheets. Utilisez une liste CSV de tickets pour :

<!-- vale gitlab_base.Spelling = YES -->

- Créer un instantané des tickets pour une analyse hors ligne ou pour les partager avec d'autres équipes qui ne sont peut-être pas dans GitLab.
- Créer des diagrammes, des graphiques et des tableaux à partir des données CSV.
- Convertir les données vers d'autres formats à des fins d'audit ou de partage.
- Importer les tickets dans un système externe à GitLab.
- Analyser les tendances à long terme à partir de plusieurs instantanés créés au fil du temps.
- Utiliser les données à long terme pour recueillir les retours pertinents fournis dans les tickets et améliorer votre produit sur la base de métriques réelles.

## Sélectionner les tickets à exporter {#select-issues-to-export}

Vous pouvez exporter les tickets de projets individuels, mais pas de groupes.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Planifier** > **Éléments de travail**, puis filtrez par **Type** = **Ticket**.
1. Facultatif. Sélectionnez des filtres, des opérateurs et des valeurs supplémentaires pour exporter un sous-ensemble de tickets. Pour plus d'informations, consultez [filtrer la liste des tickets](managing_issues.md#filter-the-list-of-issues).
1. Dans le coin supérieur droit, sélectionnez **Actions** ({{< icon name="ellipsis_v" >}}) > **Exporter au format CSV**.
1. Dans la boîte de dialogue, vérifiez que l'adresse e-mail est correcte, puis sélectionnez **Exporter les tickets**.

Tous les tickets correspondants sont exportés, y compris ceux qui ne sont pas affichés sur la première page. Le fichier CSV exporté ne contient pas les pièces jointes des tickets.

## Format {#format}

Le fichier CSV a le format suivant :

- Le tri s'effectue par titre.
- Les colonnes sont délimitées par des virgules.
- Les champs sont entourés de guillemets doubles (`"`) si nécessaire.
- Les caractères de saut de ligne séparent les lignes.

> [!note]
> Pour plus d'informations sur les exigences d'analyse CSV pouvant affecter l'affichage des fichiers exportés dans GitLab, consultez [Considérations relatives à l'analyse CSV](../repository/files/csv.md#csv-parsing-considerations).

## Colonnes {#columns}

Les colonnes suivantes sont incluses dans le fichier CSV.

| Colonne            | Description |
| ----------------- | ----------- |
| ID                | Ticket `id`  |
| IID               | Ticket `iid` |
| Titre             | Ticket `title` |
| Description       | Ticket `description` |
| Type              | Ticket `type` |
| URL               | Un lien vers le ticket sur GitLab |
| État             | `Open` ou `Closed` |
| Confidentiel      | `Yes` ou `No` |
| Verrouillé            | `Yes` ou `No` |
| Jalon         | Titre du jalon du ticket |
| Labels            | Labels, séparés par des virgules |
| Auteur            | Nom complet de l'auteur du ticket |
| Nom d'utilisateur de l'auteur   | Nom d'utilisateur de l'auteur, sans le symbole `@` |
| Responsable          | Nom complet du responsable du ticket |
| Nom d'utilisateur du responsable | Nom d'utilisateur du responsable, sans le symbole `@` |
| Date de création (UTC)  | Formaté comme `YYYY-MM-DD HH:MM:SS` |
| Mis à jour le (UTC)  | Formaté comme `YYYY-MM-DD HH:MM:SS` |
| Fermé le (UTC)   | Formaté comme `YYYY-MM-DD HH:MM:SS` |
| Date d'échéance          | Formaté comme `YYYY-MM-DD` |
| Date de début        | Formaté comme `YYYY-MM-DD` |
| ID du parent         | ID du parent |
| IID du parent        | IID du parent |
| Titre du parent      | Titre du parent |
| Estimation de temps     | [Estimation de temps](../time_tracking.md#estimates) en secondes |
| Temps passé        | [Temps passé](../time_tracking.md#time-spent) en secondes |
| Poids            | Poids du ticket |

## Dépannage {#troubleshooting}

Lorsque vous travaillez avec des tickets exportés, vous pouvez rencontrer les problèmes suivants.

### Taille de l'export {#size-of-export}

Les tickets sont envoyés en pièce jointe d'un e-mail, avec une limite d'export de 15 Mo pour garantir une livraison réussie auprès d'un large éventail de fournisseurs de messagerie. Si vous atteignez la limite, affinez votre recherche avant l'export. Par exemple, envisagez d'exporter séparément les tickets ouverts et les tickets fermés.
