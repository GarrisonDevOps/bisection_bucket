---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Calendrier des contributions
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Le calendrier des contributions affiche les [événements d'un utilisateur](#user-contribution-events) au cours des 12 derniers mois. Cela inclut les contributions effectuées dans des dépôts dupliqués et [privés](#show-private-contributions-on-your-user-profile-page).

![Calendrier des contributions](img/contributions_calendar_v15_6.png)

La couleur de dégradé des tuiles représente le nombre de contributions effectuées par jour. Le dégradé va du blanc (0 contribution) au bleu foncé (plus de 30 contributions).

> [!note]
> Le calendrier des contributions affiche uniquement les contributions des 12 derniers mois, mais le ticket [24264](https://gitlab.com/gitlab-org/gitlab/-/issues/24264) propose de passer à plus de 12 mois. Des améliorations générales du profil utilisateur sont proposées dans le ticket [8488](https://gitlab.com/groups/gitlab-org/-/epics/8488).

Pour une vue complète de tous les événements de contribution des membres du groupe, vous pouvez utiliser les [analyses de contributions](../group/contribution_analytics/_index.md).

## Événements de contribution des utilisateurs {#user-contribution-events}

GitLab suit les événements de contribution suivants :

| Événement | Contribution |
| ----- | ------------ |
| `approved` | Merge request |
| `closed` | [Epic](../group/epics/_index.md), ticket, merge request, jalon, élément de travail |
| `commented` sur tout enregistrement `Noteable`. | Alerte, commit, design, ticket, merge request, snippet |
| `created` | Design, epic, ticket, merge request, jalon, projet, page wiki, élément de travail |
| `destroyed` | Design, jalon, page wiki |
| `expired` | Appartenance au projet |
| `joined` | Appartenance au projet |
| `left` | Appartenance au projet |
| `merged` | Merge request |
| `pushed` des commits vers (ou supprimé des commits depuis) un dépôt, individuellement ou en masse. | Projet |
| `reopened` | Epic, ticket, merge request, jalon |
| `updated` | Design, page wiki |

### Afficher les contributions quotidiennes {#view-daily-contributions}

Pour afficher vos contributions quotidiennes :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez votre nom dans la liste déroulante.
1. Dans le calendrier des contributions :
   - Pour afficher le nombre de contributions pour un jour spécifique, survolez une tuile.
   - Pour afficher toutes les contributions pour un jour spécifique, sélectionnez une tuile. Une liste affiche toutes les contributions et l'heure à laquelle elles ont été effectuées.

### Afficher les contributions privées sur votre page de profil utilisateur {#show-private-contributions-on-your-user-profile-page}

Le graphique du calendrier des contributions et la liste des activités récentes affichent vos [actions de contribution](#user-contribution-events) vers les projets privés.

Pour afficher les contributions privées :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la section **Paramètres principaux**, cochez la case **Inclure les contributions privées sur mon profil**.
1. Sélectionnez **Mettre à jour les paramètres du profil**.

## Activité des utilisateurs {#user-activity}

### Suivre l'activité d'un utilisateur {#follow-a-users-activity}

Vous pouvez suivre les utilisateurs dont l'activité vous intéresse. Le nombre maximum d'utilisateurs que vous pouvez suivre est de 300.

Pour suivre un utilisateur, vous pouvez :

- Depuis le profil d'un utilisateur, sélectionnez **Suivre**.
- Survolez le nom d'un utilisateur, puis sélectionnez **Suivre**.

Pour afficher l'activité des utilisateurs que vous suivez :

1. Dans le menu GitLab, sélectionnez **Activité**.
1. Sélectionnez l'onglet **Utilisateurs suivis**.

### Récupérer l'activité des utilisateurs sous forme de flux {#retrieve-user-activity-as-a-feed}

GitLab fournit des flux RSS de l'activité des utilisateurs. Pour vous abonner au flux RSS de l'activité d'un utilisateur :

1. Accédez au [profil de l'utilisateur](_index.md#access-your-user-profile).
1. Dans le coin supérieur droit, sélectionnez le symbole de flux ({{< icon name="rss" >}}).

L'URL du résultat contient à la fois un jeton de flux et l'activité de l'utilisateur que vous êtes autorisé à consulter. Vous pouvez ajouter cette URL à votre lecteur de flux.

### Réinitialiser le jeton de flux d'activité utilisateur {#reset-the-user-activity-feed-token}

Les jetons de flux sont sensibles et peuvent révéler des informations provenant de tickets confidentiels. Si vous pensez que votre jeton de flux a été exposé, vous devez le réinitialiser.

Pour réinitialiser votre jeton de flux :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Jetons d'accès personnel**.
1. Faites défiler vers le bas. Dans la section **Jeton de flux**, sélectionnez le lien **réinitialiser ce jeton**.
1. Dans la boîte de dialogue de confirmation, sélectionnez **OK**.

Un nouveau jeton est généré.

### Limite de la période des événements {#event-time-period-limit}

GitLab supprime de la table des événements les événements d'activité des utilisateurs de plus de 3 ans, pour des raisons de performance.
