---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Utilisez les revues de code des merge requests pour discuter et améliorer le code avant sa fusion dans votre projet.
title: Revues de merge request
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Le processus de revue de code des merge requests garantit que des experts en la matière examinent vos modifications proposées avant qu'elles ne soient fusionnées. Les relecteurs ajoutent des commentaires de revue aux merge requests et [suggèrent des modifications](suggestions.md) que l'auteur peut appliquer directement depuis l'interface GitLab.

Pour savoir comment les relecteurs sont liés aux personnes assignées, consultez [les personnes assignées et les relecteurs](../_index.md#assignees-and-reviewers).

Les relecteurs peuvent utiliser l'un de ces outils pour effectuer la revue d'une merge request :

- L'interface GitLab.
- Visual Studio Code, avec l'[extension GitLab pour VS Code](../../../../editor_extensions/visual_studio_code/_index.md).
- Une fenêtre de terminal, avec la [CLI GitLab](../../../../editor_extensions/gitlab_cli/_index.md).

Les approbations font partie des vérifications de fusion qui garantissent que votre merge request ne fusionne que lorsqu'elle est vraiment prête. Selon la configuration de votre projet, les relecteurs peuvent également bloquer la fusion d'une merge request en définissant **Demander des modifications**.

GitLab Premium et Ultimate fournissent un volet **Assigner des relecteurs** avec plus d'informations pour vous aider à trouver des relecteurs [qui satisfont les règles d'approbation](#find-reviewers-who-fulfill-approval-rules) :

![Cette merge request nécessite quatre approbations, et trois des exigences d'approbation ne sont pas satisfaites.](img/reviewer_drawer_v18_2.png)

En suivant le [processus de revue défini](#start-a-review), chaque relecteur décide d'accepter ou de rejeter une merge request. La barre latérale droite affiche la liste des relecteurs et (s'ils suivent le processus de revue) leur statut de revue :

![Exemples de relecteurs dans différents états de revue.](img/reviewer_list_v18_2.png)

- {{< icon name="dash-circle" >}} La revue n'a pas encore commencé.
- {{< icon name="status_running" >}} La revue est en cours.
- {{< icon name="check-circle" >}} Revu et approuvé.
- {{< icon name="comment-lines" >}} Revue effectuée, modifications demandées, et [cette merge request est bloquée](#prevent-merge-when-you-request-changes) jusqu'à ce que les modifications soient apportées. Ce blocage [peut être contourné](#prevent-merge-when-you-request-changes).

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une vue d'ensemble, consultez la vidéo sur la [revue de code des merge requests](https://www.youtube.com/watch?v=2MayfXKpU08&list=PLFGfElNsQthYDx0A_FaNNfUm9NHsK6zED&index=183).
<!-- Video published on 2023-04-29 -->

## Trouver des merge requests à réviser {#find-merge-requests-to-review}

Votre [page d'accueil des merge requests](../homepage.md) affiche vos merge requests en cours et les merge requests en attente de votre revue. Les merge requests que vous devez réviser se trouvent dans la catégorie **Révision demandée**. Pour voir toutes les merge requests qui nécessitent votre attention, utilisez l'une de ces méthodes :

- Appuyez sur le <kbd>raccourci clavier</kbd> <kbd>Shift</kbd>+[m](../../../shortcuts.md).
- Dans la barre latérale gauche, sélectionnez **Requêtes de fusion** ({{< icon name="merge-request" >}}).
- Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis, dans la liste déroulante, sélectionnez **Requêtes de fusion sur lesquelles je travaille**.

## Afficher le statut de revue d'une merge request {#view-the-review-status-of-a-merge-request}

Pour cela :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion** et repérez votre merge request.
1. Sélectionnez le titre de la merge request pour l'afficher.
1. Faites défiler jusqu'au [widget de merge request](../widgets.md) pour voir le statut de fusionnabilité et d'approbation de la merge request. Par exemple, l'absence des approbations requises bloque cette merge request :

   ![Le widget de merge request affiche « Toutes les approbations requises doivent être accordées ».](img/reviews_missing_v17_3.png)

## Demander une revue {#request-a-review}

{{< history >}}

- Le volet **Assigner des relecteurs** [introduit](https://gitlab.com/groups/gitlab-org/-/epics/12878) dans GitLab 17.5 [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `reviewer_assign_drawer`.
- Le volet [activé](https://gitlab.com/gitlab-org/gitlab/-/issues/467205) sur GitLab.com et GitLab Self-Managed dans GitLab 17.5.
- [Feature flag](https://gitlab.com/gitlab-org/gitlab/-/issues/467205) `reviewer_assign_drawer` supprimé dans GitLab 17.8.

{{< /history >}}

Lorsque vous avez terminé de préparer vos modifications, il est temps de demander une revue. Pour assigner un relecteur à votre merge request, utilisez la [quick action `/assign_reviewer`](../../quick_actions.md#assign_reviewer) dans n'importe quel champ de texte, ou :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion** et repérez votre merge request.
1. Sélectionnez le titre de la merge request pour l'afficher.
1. Pour trouver un relecteur par son nom : dans la barre latérale droite, dans la section **Relecteur**, sélectionnez **Modifier**.
1. Pour trouver un relecteur qui satisfait une règle d'approbation dans GitLab Premium et Ultimate :
   1. Dans la barre latérale droite, dans la section **Relecteur**, sélectionnez **Assigner** pour ouvrir le volet **Assigner des relecteurs**.
   1. Pour chaque règle d'approbation, sélectionnez **Modifier** pour trouver un relecteur qui satisfait cette règle d'approbation.

GitLab ajoute la merge request aux demandes de revue de l'utilisateur.

Pour assigner des propriétaires du code en tant que relecteurs sans les sélectionner manuellement, consultez [l'assignation automatique des relecteurs](automatic_reviewer_assignment.md).

### Trouver des relecteurs qui satisfont les règles d'approbation {#find-reviewers-who-fulfill-approval-rules}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Premium et Ultimate vous aident à trouver plus rapidement les meilleurs relecteurs pour votre merge request. Utilisez le volet **Assigner des relecteurs** pour filtrer les listes de relecteurs. Consultez les propriétaires du code pour les fichiers modifiés dans votre merge request, ainsi que les utilisateurs qui satisfont les règles d'approbation de votre projet.

Dans cet exemple, la merge request nécessite 3 approbations de propriétaires du code, mais n'en a aucune pour l'instant :

![Le volet Assigner des relecteurs pour une merge request qui nécessite 3 approbations de propriétaires du code, mais n'en a aucune. Il affiche une ligne par règle de propriétaire du code et une ligne par règle d'approbation. Sélectionnez des relecteurs pour chaque règle.](img/select_good_reviewers_v17_5.png)

Pour assigner des approbateurs éligibles dans une merge request :

1. Dans la section **Relecteur**, sélectionnez **Assigner**.
1. Pour afficher les règles d'approbation optionnelles ou les propriétaires du code, sélectionnez **Règles d'approbation optionnelles** ({{< icon name="chevron-lg-up" >}}) pour les afficher.
1. À côté du type de relecteur dont vous avez besoin, sélectionnez **Modifier** :
   - **Propriétaires du code** affiche uniquement les propriétaires du code pour ce type de fichier.
   - **Règles d'approbation** affiche uniquement les utilisateurs qui satisfont cette règle d'approbation.
1. Sélectionnez le relecteur souhaité. (GitLab Premium et Ultimate vous permettent de sélectionner plusieurs relecteurs.)
1. Répétez l'opération pour chaque élément **Propriétaire du code** et **Règle d'approbation** requis.
1. Lorsque vous avez sélectionné vos relecteurs, en haut à droite, sélectionnez **Fermer** ({{< icon name="close" >}}) pour masquer le volet **Assigner des relecteurs**.

### Redemander une revue {#re-request-a-review}

Après qu'un relecteur a terminé ses [revues de merge requests](../../../discussions/_index.md), l'auteur de la merge request peut demander une nouvelle revue au relecteur. Pour ce faire, utilisez la quick action `/request_review @user` dans n'importe quel champ de texte de la merge request, ou :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion** et repérez votre merge request.
1. Sélectionnez le titre de la merge request pour l'afficher.
1. Si vous avez réduit la barre latérale droite dans la merge request, sélectionnez {{< icon name="chevron-double-lg-left" >}} **Développer la barre latérale** pour la développer.
1. Dans la section **Relecteur**, sélectionnez l'icône **Redemander une revue** ({{< icon name="redo" >}}) à côté du nom du relecteur.

GitLab crée un nouvel [élément de la liste de tâches](../../../todos.md) pour le relecteur et lui envoie un e-mail de notification.

## Démarrer une révision {#start-a-review}

{{< history >}}

- Le volet **Assigner des relecteurs** [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/185795) dans GitLab 17.11 [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `improved_review_experience`. Désactivé par défaut. Fonctionnalité désactivée par défaut.
- Le volet **Assigner des relecteurs** [activé par défaut](https://gitlab.com/gitlab-org/gitlab/-/issues/535461) dans GitLab 18.1.

{{< /history >}}

Lors de la revue d'une merge request, suivez le processus de revue plutôt que de laisser des commentaires individuels. Lorsque vous sélectionnez **Démarrer une révision**, la section **Relecteur** de la barre latérale droite met à jour votre statut de **En attente de révision** ({{< icon name="dash-circle" >}}) à **Le relecteur ou la relectrice a commencé la révision** ({{< icon name="comment-dots" >}}).

Pour commencer votre revue d'une merge request :

1. L'une ou l'autre des options :
   - Appuyez sur <kbd>Shift</kbd>+<kbd>r</kbd> pour accéder à votre page **Requêtes de fusion**.
   - Dans le coin supérieur droit, sélectionnez **Requêtes de fusion** ({{< icon name="merge-request" >}}).

1. Trouvez votre merge request et sélectionnez son titre pour l'afficher.
1. Lisez la description et les commentaires de la merge request pour en apprendre davantage sur elle.
1. Sélectionnez **Modifications** pour afficher le diff des modifications proposées. Pour en savoir plus sur la page **Modifications**, consultez [les modifications dans les merge requests](../changes.md).
1. [Suggérez des modifications multi-lignes ou sur une seule ligne](suggestions.md) si nécessaire. Lorsque vous êtes prêt à enregistrer votre premier commentaire de revue, sélectionnez **Démarrer une révision** pour :

   - Mettre à jour votre statut dans la barre latérale droite à **Le relecteur ou la relectrice a commencé la révision** ({{< icon name="comment-dots" >}}).
   - Enregistrer votre commentaire de revue, mais le laisser non publié, comme ceci :

     ![Un commentaire de revue multi-lignes non publié affiché comme « En attente ».](img/pending_state_v18_1.png)

   Si vous sélectionnez **Ajouter un commentaire** au lieu de **Démarrer une révision**, GitLab publie votre commentaire immédiatement.

1. Continuez à rédiger des commentaires de revue dans l'onglet **Modifications** ou dans l'onglet **Vue d'ensemble**. Sélectionner **Ajouter à la revue de code** les maintient non publiés jusqu'à ce que vous soumettiez votre revue :

   ![Nouveau fil de discussion](img/mr_review_new_comment_v16_6.png)

Ensuite, soumettez votre revue.

### Résoudre ou rouvrir un fil de discussion avec un commentaire {#resolve-or-reopen-thread-with-a-comment}

Les commentaires peuvent également résoudre ou rouvrir des fils de commentaires. Pour résoudre ou rouvrir un fil de discussion lors d'une réponse à un commentaire :

1. Dans la zone de texte du commentaire, rédigez votre commentaire.
1. Cochez ou décochez **Résoudre le fil de conversation** ou **Rouvrir le fil de conversation**.
1. Sélectionnez **Ajouter un commentaire** ou **Ajouter à la revue de code**.

Les commentaires en attente affichent des informations sur les actions différées. Ces actions s'exécuteront lorsque vous soumettrez une revue.

## Soumettre une revue {#submit-a-review}

{{< history >}}

- Utilisation de **Approuver** pour soumettre des commentaires de revue en attente [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/562579) dans GitLab 18.6.

{{< /history >}}

Lorsque vous soumettez une revue, GitLab :

- Publie les commentaires de votre revue.
- Envoie un seul e-mail à chaque utilisateur notifiable de la merge request, avec vos commentaires de revue en pièce jointe. Répondre à cet e-mail crée un nouveau commentaire sur la merge request.
- Exécute toutes les quick actions que vous avez ajoutées à vos commentaires de revue.
- Affiche le résultat de votre revue.

Pour soumettre rapidement votre revue d'une merge request :

- Accédez au widget de merge request et sélectionnez **Approuver**. La merge request est également approuvée par vous.
- Utilisez la [quick action `/submit_review`](../../quick_actions.md#submit_review) dans le texte d'un commentaire hors revue.

Pour lire et modifier vos commentaires de revue lors de la soumission de votre revue :

1. En haut à droite, sélectionnez **Votre révision** pour afficher les détails de votre revue :

   ![Le volet de revue, affichant une revue en cours. Il contient un commentaire de revue sur une seule ligne et un commentaire s'étendant sur deux lignes de code.](img/review_drawer_v18_3.png)

1. Vérifiez vos commentaires en attente. Modifiez-les si nécessaire.
1. Sélectionnez le résultat de votre revue.

   - **Approuver** : laissez un commentaire et approuvez les modifications.
   - **Commentaire** : laissez un commentaire général sans approbation explicite ni demande de modification.
   - **Demander des modifications** : bloquer la fusion de la merge request jusqu'à ce que l'auteur traite vos commentaires.

1. Facultatif. Rédigez un résumé de votre revue. Les utilisateurs de GitLab Premium et Ultimate peuvent sélectionner **Ajouter un résumé** ({{< icon name="tanuki-ai" >}}) pour créer un résumé à leur place. Incluez toutes les quick actions que vous souhaitez exécuter.

### Rejeter votre revue en attente {#discard-your-pending-review}

Lorsque vous rejetez une revue, vos commentaires non publiés sont supprimés et vous ne pouvez pas les restaurer. Pour cela :

1. En haut à droite, sélectionnez **Votre révision** pour afficher les détails de votre revue :

   ![Le volet de revue, affichant une revue en cours. Il contient un commentaire de revue sur une seule ligne et un commentaire s'étendant sur deux lignes de code.](img/review_drawer_v18_3.png)

1. Sélectionnez **Rejeter la revue**.

### Empêcher la fusion lors d'une demande de modifications {#prevent-merge-when-you-request-changes}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/430728) dans GitLab 16.11 [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `mr_reviewer_requests_changes`. Fonctionnalité désactivée par défaut.
- Activé par défaut [sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/451211) et [GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/158226) dans GitLab 17.2.
- [Feature flag supprimé](https://gitlab.com/gitlab-org/gitlab/-/issues/451211) dans GitLab 17.3.

{{< /history >}}

Un relecteur [demandant des modifications](#submit-a-review) bloque la fusion d'une merge request. Dans ce cas, la zone des rapports de merge request affiche le message **Les demandes de modifications doivent être approuvées par l'utilisateur demandeur**. Pour débloquer la merge request, le relecteur qui a demandé des modifications doit [réviser à nouveau et approuver](#re-request-a-review) la merge request.

### Supprimer une demande de modification {#remove-a-change-request}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/480412) dans GitLab 17.8.

{{< /history >}}

Si vous avez précédemment demandé des modifications, vous pouvez supprimer votre demande de modification. Vous pourriez avoir besoin de le faire si les deux conditions suivantes sont vraies :

- Vous ne pouvez plus approuver la merge request.
- Vous souhaitez annuler votre demande de modification, mais ne voulez pas soumettre une nouvelle revue.

Pour supprimer votre demande de modification sans soumettre une nouvelle revue :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion** et repérez votre merge request.
1. Sélectionnez le titre de la merge request pour l'afficher.
1. Dans la **Vue d'ensemble** de la merge request, faites défiler jusqu'à la zone des rapports de merge request.
1. À côté de **Les demandes de modifications doivent être approuvées par l'utilisateur demandeur**, sélectionnez **Supprimer** :

   ![Une merge request bloquée car un utilisateur a demandé des modifications](img/remove_v17_8.png)

### Contourner une demande de modification {#bypass-a-request-for-changes}

Si l'utilisateur qui a demandé des modifications n'est pas disponible pour réviser à nouveau ou approuver, un autre utilisateur disposant de l'autorisation de fusionner la merge request peut ignorer cette vérification :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion** et repérez votre merge request.
1. Sélectionnez le titre de la merge request pour l'afficher.
1. Dans la **Vue d'ensemble** de la merge request, faites défiler jusqu'à la zone des rapports de merge request.
1. À côté de **Les demandes de modifications doivent être approuvées par l'utilisateur demandeur**, sélectionnez **Contourner** :

   ![Une merge request bloquée car un utilisateur a demandé des modifications](img/bypass_v17_2.png)

1. La zone des rapports de fusion affiche `Merge with caution: Override added`. Pour voir quelle vérification un utilisateur a contournée, sélectionnez **Étendre les vérifications de fusion** ({{< icon name="chevron-lg-down" >}}) et trouvez la vérification qui contient une icône d'avertissement ({{< icon name="status_warning" >}}). Dans cet exemple, l'auteur a contourné **Les demandes de modifications doivent être approuvées par l'utilisateur demandeur** :

   ![Cette merge request contient une vérification contournée et doit être fusionnée avec précaution.](img/status_warning_v17_4.png)

## Télécharger les modifications d'une merge request {#download-merge-request-changes}

Vous pouvez [télécharger les modifications d'une merge request](../changes.md#download-merge-request-changes) sous forme de fichier diff ou de correctif.

## Fonctionnalités associées {#associated-features}

Les merge requests sont liées à ces fonctionnalités :

- [Effectuer un cherry-pick des modifications](../cherry_pick_changes.md) : dans l'interface GitLab, sélectionnez **Effectuer un cherry-pick** dans une merge request fusionnée ou un commit pour effectuer un cherry-pick.
- [Comparer les modifications](../changes.md) : affichez et téléchargez le diff des modifications incluses dans une merge request.
- [Merge requests en avance rapide](../methods/_index.md#fast-forward-merge) : pour un historique Git linéaire et un moyen d'accepter des merge requests sans créer de commits de fusion
- [Trouver la merge request qui a introduit une modification](../versions.md) : lors de l'affichage de la page des détails du commit, GitLab crée des liens vers les merge requests contenant ce commit.
- [Versions des merge requests](../versions.md) : sélectionnez et comparez les différentes versions des diffs de merge requests
- [Résoudre les conflits](../conflicts.md) : GitLab peut fournir l'option de résoudre certains conflits de merge requests dans l'interface GitLab.
- [Annuler des modifications](../revert_changes.md) : annulez les modifications de n'importe quel commit d'une merge request.
- [Raccourcis clavier](../../../shortcuts.md#merge-requests) : accédez à des parties spécifiques d'une merge request et modifiez-les à l'aide de commandes clavier.
- [Analyse du flux de valeur](../../../group/value_stream_analytics/_index.md) : suivez les étapes clés des merge requests (telles que `reviewed` et `approved`) pour identifier où votre équipe passe le plus de temps dans le cycle de développement logiciel. Ces informations aident à découvrir des insights exploitables pour optimiser les workflows des merge requests pour les groupes et les projets, et améliorer la productivité des équipes de développement. Consultez [comment nous avons réduit le temps de revue des MR grâce à l'analyse du flux de valeur](https://about.gitlab.com/blog/how-we-reduced-mr-review-time-with-value-stream-management/) dans cet article de blog.

## Sujets connexes {#related-topics}

- [Comparer les modifications dans les merge requests](../changes.md)
- [Comparer les révisions](../../repository/compare_revisions.md)
- [Méthodes de fusion](../methods/_index.md)
- [API des notes brouillon](../../../../api/draft_notes.md)
