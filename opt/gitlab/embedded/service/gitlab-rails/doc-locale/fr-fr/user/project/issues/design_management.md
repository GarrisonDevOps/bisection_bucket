---
stage: Plan
group: Portfolio Planning
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Gestion des designs (obsolète)
---

<!--- start_remove The following content will be removed on remove_date: '2027-05-15' -->

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> Cette fonctionnalité a été [dépréciée](../../../update/deprecations.md#design-management-deprecated) dans GitLab 18.6 et sa suppression est prévue dans la version 20.0. Ce changement est un changement de rupture. À partir de GitLab 20.0, les utilisateurs ne pourront plus importer de nouveaux designs. Les designs existants restent disponibles en mode lecture seule jusqu'à GitLab 21.0, laissant aux utilisateurs le temps de sauvegarder leurs designs selon leurs besoins. GitLab explore des alternatives qui s'intègrent mieux aux outils déjà utilisés par les designers.

<!--- end_remove -->

La gestion des designs vous permet d'importer des ressources de design (notamment des maquettes filaires et des prototypes) dans les tickets GitLab et de les conserver à un seul endroit. Les designers produit, les chefs de produit et les ingénieurs peuvent collaborer sur les designs avec une source unique de vérité.

Vous pouvez partager des prototypes de designs avec votre équipe, ou consulter et traiter les régressions visuelles.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une présentation vidéo, consultez [Design Management](https://www.youtube.com/watch?v=CCMtCqdK_aM).
<!-- Video published on 2019-07-11 -->

## Prérequis {#prerequisites}

- [Git Large File Storage (LFS)](../../../topics/git/lfs/_index.md) doit être activé :
  - Sur GitLab.com, LFS est déjà activé.
  - Sur les instances GitLab Self-Managed, un administrateur GitLab doit [activer LFS globalement](../../../administration/lfs/_index.md).
  - Sur GitLab.com et les instances GitLab Self-Managed, LFS doit être [activé pour le projet lui-même](../settings/_index.md#configure-project-features-and-permissions). Si LFS est activé globalement, il est activé par défaut pour tous les projets. Si vous l'avez désactivé pour votre projet, vous devez le réactiver.

  Les designs sont stockés en tant qu'objets LFS. Les miniatures d'images sont stockées comme d'autres uploads et ne sont pas associées à un projet, mais plutôt à un modèle de design spécifique.

  Un administrateur GitLab peut vérifier le chemin relatif d'un projet stocké par hachage en accédant à **Admin** > **Projets**, puis en sélectionnant le projet en question. Le champ **Chemin relatif** contient `@hashed` dans sa valeur.

Si les conditions requises ne sont pas remplies, vous en êtes informé dans la section **Designs**.

## Types de fichiers pris en charge {#supported-file-types}

Vous pouvez importer des fichiers des types suivants en tant que designs :

- BMP
- GIF
- ICO
- JPEG
- JPG
- PNG
- TIFF
- WEBP

La prise en charge des fichiers PDF est suivie dans [le ticket 32811](https://gitlab.com/gitlab-org/gitlab/-/issues/32811).

## Afficher un design {#view-a-design}

La section **Designs** se trouve dans la description du ticket.

Prérequis :

- Vous devez disposer du rôle Invité, Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet.

Pour afficher un design :

1. Accédez à un ticket.
1. Dans la section **Designs**, sélectionnez l'image de design que vous souhaitez afficher.

Le design sélectionné s'ouvre. Vous pouvez ensuite [zoomer](#zoom-in-on-a-design) dessus ou [créer un commentaire](#add-a-comment-to-a-design).

![La section « Designs » dans un ticket GitLab, affichant des prototypes de designs importés.](img/design_management_v14_10.png)

Lors de l'affichage d'un design, vous pouvez naviguer vers d'autres designs. Pour ce faire, effectuez l'une des actions suivantes :

- Dans le coin supérieur droit, sélectionnez **Aller au design précédent** ({{< icon name="chevron-lg-left" >}}) ou **Aller au design suivant** ({{< icon name="chevron-lg-right" >}}).
- Appuyez sur <kbd>Gauche</kbd> ou <kbd>Droite</kbd> sur votre clavier.

Pour revenir à la vue du ticket, effectuez l'une des actions suivantes :

- Dans le coin supérieur gauche, sélectionnez l'icône de fermeture ({{< icon name="close" >}}).
- Appuyez sur <kbd>Échap</kbd> sur votre clavier.

Lorsqu'un design est ajouté, une icône verte ({{< icon name="plus-square" >}}) s'affiche sur la miniature de l'image. Lorsqu'un design a été [modifié](#add-a-new-version-of-a-design) dans la version actuelle, une icône bleue ({{< icon name="file-modified-solid" >}}) s'affiche.

### Zoomer sur un design {#zoom-in-on-a-design}

Vous pouvez explorer un design plus en détail en effectuant un zoom avant ou arrière sur l'image :

- Pour contrôler le niveau de zoom, sélectionnez plus (`+`) et moins (`-`) au bas de l'image.
- Pour réinitialiser le niveau de zoom, sélectionnez l'icône de rétablissement ({{< icon name="redo" >}}).

Pour vous déplacer dans l'image en mode zoom, faites glisser l'image.

## Télécharger une image de design avec un jeton d'accès {#download-a-design-image-with-an-access-token}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246866) dans GitLab 19.3.

{{< /history >}}

Utilisez un jeton d'accès pour télécharger des images de design depuis des clients API tels que des applications mobiles, des intégrations et des exportateurs, lorsqu'aucune session de navigateur n'est disponible.

Prérequis :

- Vous devez disposer de l'un des jetons suivants :
  - Un [jeton d'accès personnel](../../profile/personal_access_tokens.md) ou un [jeton OAuth 2.0](../../../api/oauth2.md) avec la portée `api` ou `read_api`.
  - Un [jeton d'accès personnel à granularité fine](../../../auth/tokens/fine_grained_access_tokens.md) avec l'autorisation **Élément de travail : lecture** pour le projet.
- Vous devez avoir l'autorisation de [consulter le design](#view-a-design).

Vous ne pouvez pas utiliser de jetons d'accès au projet, de jetons d'accès de groupe ou de jetons de compte de service pour télécharger des images de design.

Pour télécharger une image de design :

1. Obtenez l'URL de l'image depuis l'API GraphQL. Pour un aperçu ne dépassant pas 432x230 pixels, utilisez le champ `imageV432x230` à la place de `image` :

   ```graphql
   query {
     project(fullPath: "my-group/my-project") {
       issue(iid: "1") {
         designCollection {
           designs {
             nodes {
               filename
               image
             }
           }
         }
       }
     }
   }
   ```

1. Effectuez une requête vers l'URL de l'image et transmettez le jeton dans l'en-tête `PRIVATE-TOKEN` :

   ```shell
   curl --output design.png --header "PRIVATE-TOKEN: <your_access_token>" "<image_url>"
   ```

   Pour les jetons OAuth 2.0, utilisez plutôt l'en-tête `Authorization: Bearer <oauth_token>`. Vous devez envoyer le jeton dans un en-tête de requête. Les jetons dans les paramètres de chaîne de requête, tels que `private_token`, ne sont pas acceptés.

## Ajouter un design à un ticket {#add-a-design-to-an-issue}

{{< history >}}

- Le rôle minimum pour ajouter un design à un ticket a [changé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet.
- Les noms des fichiers importés ne doivent pas dépasser 255 caractères.

Pour ajouter un design à un ticket :

1. Accédez à un ticket.
1. L'une ou l'autre des options :
   - Sélectionnez **Importer des designs**, puis sélectionnez des images depuis votre explorateur de fichiers. Vous pouvez sélectionner jusqu'à 10 fichiers à la fois.
     <!-- vale gitlab_base.SubstitutionWarning = NO -->
   - Sélectionnez **cliquer pour importer**, puis sélectionnez des images depuis votre explorateur de fichiers. Vous pouvez sélectionner jusqu'à 10 fichiers à la fois.
     <!-- vale gitlab_base.SubstitutionWarning = YES -->

   - Faites glisser un fichier depuis votre explorateur de fichiers et déposez-le dans la zone de dépôt de la section **Designs**.

     ![Import d'un nouveau design par glisser-déposer sur la page du ticket.](img/design_drag_and_drop_uploads_v13_2.png)

   - Prenez une capture d'écran ou copiez un fichier image local dans votre presse-papiers, survolez la zone de dépôt avec votre curseur, puis appuyez sur <kbd>Ctrl</kbd> ou <kbd>Commande</kbd>+<kbd>V</kbd>.

     Lorsque vous collez des images de cette façon, gardez les points suivants à l'esprit :

     - Vous ne pouvez coller qu'une seule image à la fois. Lorsque vous collez plusieurs fichiers copiés, seul le premier est importé.
     - Si vous collez une capture d'écran, l'image est ajoutée en tant que fichier PNG avec un nom généré : `design_<timestamp>.png`.
     - Cette fonctionnalité n'est pas prise en charge dans Internet Explorer.

## Ajouter une nouvelle version d'un design {#add-a-new-version-of-a-design}

{{< history >}}

- Le rôle minimum pour ajouter une nouvelle version d'un design a [changé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Au fur et à mesure que la discussion sur un design avance, vous pouvez vouloir importer une nouvelle version d'un design.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet.

Pour ce faire, [ajoutez un design](#add-a-design-to-an-issue) avec le même nom de fichier.

Pour parcourir toutes les versions du design, utilisez la liste déroulante en haut de la section **Designs**. Elle s'affiche sous la forme **Affichage de la dernière version** ou **Affichage de la version N°**.

### Designs ignorés {#skipped-designs}

Lorsque vous importez une image avec le même nom de fichier qu'un design déjà importé et que cette image est identique, elle est ignorée. Cela signifie qu'aucune nouvelle version du design n'est créée. Lorsque des designs sont ignorés, un message d'avertissement s'affiche.

## Archiver un design {#archive-a-design}

{{< history >}}

- Le rôle minimum pour archiver un design a [changé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Vous pouvez archiver des designs individuellement ou en sélectionner plusieurs à archiver simultanément.

Les designs archivés ne sont pas définitivement perdus. Vous pouvez consulter les [versions précédentes](#add-a-new-version-of-a-design).

Lorsque vous archivez un design, son URL change. Si le design n'est pas disponible dans la dernière version, vous ne pouvez le lier qu'avec la version dans l'URL.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet.
- Vous pouvez archiver uniquement la dernière version d'un design.

Pour archiver un design unique :

1. Sélectionnez le design pour l'afficher en grand.
1. Dans le coin supérieur droit, sélectionnez **Archiver le design** ({{< icon name="archive" >}}).
1. Sélectionnez **Archiver les designs**.

Pour archiver plusieurs designs à la fois :

1. Cochez les cases des designs que vous souhaitez archiver.
1. Sélectionnez **Archiver la sélection**.

## Persistance des données de gestion des designs {#design-management-data-persistence}

- Les données de gestion des designs ne sont pas supprimées lorsque :
  - [Un projet est supprimé](https://gitlab.com/gitlab-org/gitlab/-/issues/13429).
  - [Un ticket est supprimé](https://gitlab.com/gitlab-org/gitlab/-/issues/13427).

### Répliquer les données de gestion des designs {#replicate-design-management-data}

Les données de gestion des designs peuvent être [répliquées](../../../administration/geo/replication/datatypes.md#replicated-data-types) et vérifiées par Geo. Pour plus d'informations, consultez [le ticket 355660](https://gitlab.com/gitlab-org/gitlab/-/issues/355660).

## Éditeurs Markdown et de texte enrichi pour les descriptions {#markdown-and-rich-text-editors-for-descriptions}

Vous pouvez utiliser l'éditeur Markdown et de texte enrichi dans les descriptions de designs. C'est le même éditeur que celui que vous utilisez pour les commentaires dans GitLab.

## Réorganiser les designs {#reorder-designs}

Vous pouvez modifier l'ordre des designs en les faisant glisser vers une nouvelle position.

## Ajouter un commentaire à un design {#add-a-comment-to-a-design}

Vous pouvez démarrer des [discussions](../../discussions/_index.md) sur les designs importés. Pour ce faire :

1. Accédez à un ticket.
1. Sélectionnez le design.
1. Sélectionnez l'image. Une épingle est créée à cet endroit, indiquant l'emplacement de la discussion.
1. Saisissez votre message.
1. Sélectionnez **Commentaire**.

Vous pouvez ajuster la position d'une épingle en la faisant glisser sur l'image. Utilisez cette option lorsque la mise en page de votre design a changé, ou pour déplacer une épingle afin d'en ajouter une nouvelle à sa place.

Les nouveaux fils de discussion reçoivent des numéros d'épingle différents, que vous pouvez utiliser pour les référencer.

Les nouvelles discussions sont affichées dans l'activité du ticket, afin que toutes les personnes concernées puissent y participer.

## Supprimer un commentaire d'un design {#delete-a-comment-from-a-design}

{{< history >}}

- Le rôle minimum pour supprimer un commentaire d'un design a [changé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet.

Pour supprimer un commentaire d'un design :

1. Sur le commentaire que vous souhaitez supprimer, sélectionnez **Plus d'actions** {{< icon name="ellipsis_v" >}} > **Supprimer le commentaire**.
1. Dans la boîte de dialogue de confirmation, sélectionnez **Supprimer le commentaire**.

## Résoudre un fil de discussion sur un design {#resolve-a-discussion-thread-on-a-design}

Lorsque vous avez terminé de discuter d'une partie d'un design, vous pouvez résoudre le fil de discussion.

Pour marquer un fil de discussion comme résolu ou ouvert, effectuez l'une des actions suivantes :

- Dans le coin supérieur droit du premier commentaire de la discussion, sélectionnez **Résoudre le fil de conversation** ou **Rouvrir le fil de conversation** ({{< icon name="check-circle" >}}).
- Ajoutez un nouveau commentaire au fil de discussion et cochez ou décochez la case **Résoudre le fil de conversation**.

La résolution d'un fil de discussion marque également comme effectués tous les [éléments de la liste de tâches](../../todos.md) en attente liés aux notes du fil. Seuls les éléments de la liste de tâches de l'utilisateur déclenchant l'action sont affectés.

Les épingles de commentaires résolus disparaissent du design pour libérer de l'espace pour de nouvelles discussions. Pour consulter une discussion résolue, développez **Commentaires résolus** sous les fils de discussion visibles.

## Ajouter un élément de la liste de tâches pour un design {#add-a-to-do-item-for-a-design}

Pour ajouter un [élément de la liste de tâches](../../todos.md) pour un design, sélectionnez **Ajouter une tâche à faire** dans la barre latérale du design.

## Référencer un design en Markdown {#refer-to-a-design-in-markdown}

Vous pouvez référencer un design dans une zone de texte [Markdown](../../markdown.md). Collez l'URL brute du design dans un commentaire ou une description. Elle s'affiche alors sous la forme d'une référence abrégée.

Par exemple, si vous référencez un design comme suit :

```markdown
See https://gitlab.com/gitlab-org/gitlab/-/issues/13195/designs/Group_view.png.
```

GitLab restitue automatiquement les URL brutes sous la forme d'une [référence](../../markdown.md#gitlab-specific-references) abrégée : `See #13195[Group_view.png].`

Créer un lien vers une image est différent d'[intégrer l'image](../../markdown.md#images) dans un commentaire ou une description. Il n'est pas possible d'intégrer un design de cette façon.

## Journaux d'activité des designs {#design-activity-records}

Les événements d'activité des utilisateurs sur les designs (création, suppression et mises à jour) sont suivis par GitLab et affichés sur les pages d'activité du [profil utilisateur](../../profile/_index.md#access-your-user-profile), du [groupe](../../group/manage.md#view-group-activity) et du [projet](../working_with_projects.md#view-project-activity).

## Plugin GitLab-Figma {#gitlab-figma-plugin}

Vous pouvez utiliser le plugin GitLab-Figma pour importer vos designs depuis Figma directement dans vos tickets GitLab.

Pour utiliser le plugin dans Figma, installez-le depuis le [répertoire Figma](https://www.figma.com/community/plugin/860845891704482356/gitlab) et connectez-vous à GitLab via un jeton d'accès personnel.

Pour plus d'informations, consultez la [documentation du plugin](https://gitlab.com/gitlab-org/gitlab-figma-plugin/-/wikis/home).

## Dépannage {#troubleshooting}

Lorsque vous utilisez la gestion des designs, vous pouvez rencontrer les problèmes suivants.

### Design introuvable {#could-not-find-design}

Vous pouvez obtenir une erreur indiquant `Could not find design`.

Ce problème survient lorsqu'un design a été [archivé](#archive-a-design), et n'est donc pas disponible dans la dernière version, et que le lien que vous avez suivi ne spécifie pas de version.

Lorsque vous archivez un design, son URL change. Si le design n'est pas disponible dans la dernière version, il ne peut être lié qu'avec la version dans l'URL.

Par exemple, `https://gitlab.example.com/mygroup/myproject/-/issues/123456/designs/menu.png?version=503554`. Vous ne pouvez plus accéder à `menu.png` avec `https://gitlab.example.com/mygroup/myproject/-/issues/123456/designs/menu.png`.

La solution de contournement consiste à sélectionner l'une des versions précédentes dans la liste déroulante en haut de la section **Designs**. Elle s'affiche sous la forme **Affichage de la dernière version** ou **Affichage de la version N°**.

[Le ticket 392540](https://gitlab.com/gitlab-org/gitlab/-/issues/392540) suit l'amélioration de ce comportement.
