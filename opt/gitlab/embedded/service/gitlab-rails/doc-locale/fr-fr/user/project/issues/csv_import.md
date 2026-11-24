---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Importer des tickets depuis un fichier CSV
description: "Importez des tickets dans un projet en chargeant un fichier CSV."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Également [autorisé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) pour le rôle Planificateur dans GitLab 17.7.
- Prise en charge de la colonne `type` [ajoutée](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/199945) dans GitLab 18.4.

{{< /history >}}

Vous pouvez importer des tickets dans un projet en chargeant un fichier CSV (valeurs séparées par des virgules) contenant les colonnes suivantes :

| Nom          | Obligatoire                             | Description |
| ------------- | ------------------------------------ | ----------- |
| `title`       | {{< yes >}} | Titre du ticket. |
| `description` | {{< yes >}} | Description du ticket. |
| `due_date`    | {{< no >}} | Date d'échéance du ticket au format `YYYY-MM-DD`. |
| `milestone`   | {{< no >}} | Titre du jalon du ticket. |
| `type`        | {{< no >}} | Type de ticket. [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200893) dans GitLab 18.4. |

Les données des autres colonnes ne sont pas importées.

Vous pouvez utiliser le champ `description` pour intégrer des [actions rapides](../quick_actions.md) et ajouter d'autres données au ticket. Par exemple, des labels, des personnes assignées et des jalons.

Vous pouvez également [déplacer un ticket](managing_issues.md#move-an-issue). Le déplacement des tickets préserve davantage de données.

L'utilisateur qui charge le fichier CSV est défini comme auteur des tickets importés.

Vous devez disposer du rôle Planificateur, Reporter, Responsable sécurité, Developer, Maintainer ou Owner pour un projet afin d'importer des tickets.

## Préparer l'importation {#prepare-for-the-import}

- Envisagez d'importer un fichier test contenant seulement quelques tickets. Il n'est pas possible d'annuler une importation volumineuse sans utiliser l'API GitLab.
- Assurez-vous que votre fichier CSV respecte les exigences de [format de fichier](#csv-file-format).
- Si votre fichier CSV inclut l'en-tête milestone, assurez-vous que tous les titres de jalons uniques présents dans le fichier existent déjà dans le projet ou ses groupes parents.

## Importer le fichier {#import-the-file}

Pour importer des tickets :

1. Accédez à la page **Tickets** de votre projet.
1. Ouvrez la fonctionnalité d'importation selon que le projet contient ou non des tickets :
   - Le projet contient des tickets existants : dans le coin supérieur droit, à côté de **Modification en masse**, sélectionnez **Actions** ({{< icon name="ellipsis_v" >}}) > **Importer un fichier CSV**.
   - Le projet ne contient aucun ticket : au milieu de la page, sélectionnez **Importer un fichier CSV**.
1. Sélectionnez le fichier à importer, puis sélectionnez **Importer des tickets**.

Le fichier est traité en arrière-plan et un e-mail de notification vous est envoyé si des erreurs sont détectées ou une fois l'importation terminée.

## Format de fichier CSV {#csv-file-format}

Pour importer des tickets, GitLab exige que les fichiers CSV respectent un format spécifique.

> [!note]
> Pour plus d'informations sur les exigences d'analyse CSV susceptibles d'affecter l'affichage des fichiers importés dans GitLab, consultez [Considérations relatives à l'analyse CSV](../repository/files/csv.md#csv-parsing-considerations).

| Élément                | Format |
| ---------------------- | ------ |
| ligne d'en-tête             | Les fichiers CSV doivent inclure les en-têtes suivants : `title` et `description`. La casse des en-têtes n'a pas d'importance. |
| colonnes                | Les données des colonnes autres que `title`, `description`, `due_date`, `milestone` et `type` ne sont pas importées. |
| séparateurs             | Le séparateur de colonnes est détecté à partir de la ligne d'en-tête. Les caractères séparateurs pris en charge sont la virgule (`,`), le point-virgule (`;`) et la tabulation (`\t`). Le séparateur de lignes peut être `CRLF` ou `LF`. |
| guillemet double | Le caractère guillemet double (`"`) est utilisé pour délimiter les champs, permettant ainsi l'utilisation du séparateur de colonnes dans un champ (voir la troisième ligne dans l'exemple de données CSV ci-dessous). Pour insérer un guillemet double (`"`) dans un champ délimité, utilisez deux guillemets doubles successifs (`""`). |
| lignes de données              | Après la ligne d'en-tête, les lignes suivantes doivent utiliser le même ordre de colonnes. Le titre du ticket est obligatoire, mais la description est facultative. |

Si vous utilisez des caractères spéciaux (par exemple, `,` ou `\n`) ou plusieurs lignes dans un champ (par exemple, lors de l'utilisation des [actions rapides](../quick_actions.md)), entourez les caractères de guillemets doubles (`"`).

Également lors de l'utilisation des [actions rapides](../quick_actions.md) :

- Chaque action doit être sur une ligne distincte.
- Pour les actions rapides telles que `/label` et `/milestone`, le label ou le jalon doit déjà exister dans le projet.
- L'utilisateur auquel vous assignez le ticket doit être membre du projet.

Exemple de données CSV :

```plaintext
title,description,due_date,milestone
My Issue Title,My Issue Description,2022-06-28
Another Title,"A description, with a comma",
"One More Title","One More Description",
An Issue with Quick Actions,"Hey can we change the frontend?

/assign @sjones
/label ~frontend ~documentation",
An issue with milestone,"My milestone is created",,v1.0
```

### Taille du fichier {#file-size}

La limite dépend du mode d'hébergement de votre instance GitLab :

- GitLab Self-Managed : définie par la valeur de configuration `Max Attachment Size` pour l'instance GitLab.
- GitLab.com : limitée à 10 Mo.
