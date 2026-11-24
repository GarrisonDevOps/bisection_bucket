---
stage: Monetization
group: Subscription Lifecycle
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Consultez votre engagement et votre utilisation GitLab Flex, ajustez votre réservation et contrôlez vos dépenses."
title: Tableau de bord Flex
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Introduction dans GitLab 19.1.

{{< /history >}}

Le tableau de bord Flex vous permet de suivre votre engagement et votre utilisation de [GitLab Flex](gitlab_flex.md), de définir votre réservation mensuelle et de contrôler vos dépenses.

## Panneaux {#panels}

Le tableau de bord Flex comporte deux niveaux. La page principale affiche votre engagement sur toute la durée du contrat. La sélection d'un mois affiche votre utilisation et votre réservation pour ce mois.

### Durée du contrat {#contract-term}

La page principale affiche :

- **Engagement contractuel** : votre engagement total pour la durée du contrat, le montant utilisé à ce jour et le montant restant.
- **Dépenses à la demande** : vos dépenses totales à la demande pour la durée du contrat.
- **Durée du contrat** : les dates de début et de fin de votre contrat, la période de facturation en cours et votre réservation mensuelle minimale.

En dessous, un tableau liste chaque mois de la durée de votre contrat :

- **Mois** : la période de facturation. Sélectionnez un mois passé, en cours ou à venir pour l'afficher en détail.
- **Statut** : la position du mois dans la durée de votre contrat :
  - **Mois passé** et **Mois en cours** : la réservation est verrouillée.
  - **À venir** : le mois suivant. C'est le seul mois dont vous pouvez modifier la réservation.
  - **Mois futur** : les mois suivant le mois à venir. Ils sont verrouillés jusqu'à ce qu'ils deviennent le mois à venir.
- **Réserver avant** : définissez la réservation pour ce mois avant cette date.
- **Réservé** : le montant réservé pour ce mois.
- **À la demande** : utilisation à la demande pour ce mois.
- **Dépenses réelles** : votre réservation plus l'utilisation à la demande.

### Vue d'ensemble du mois {#month-overview}

Sélectionnez le mois en cours ou un mois passé pour consulter votre utilisation par rapport à la réservation engagée pour ce mois.

La vue d'ensemble du mois affiche :

- **Réservation mensuelle totale** : le montant réservé pour le mois, réparti entre les sièges et les capacités basées sur des crédits.
- **Sièges** : sièges utilisés par rapport à votre réservation.
- **Crédits Gitlab** : Crédits utilisés pour le mois par capacité, répartis entre les crédits prélevés sur votre réservation et les crédits à la demande.

Un tableau détaille chaque capacité de votre réservation, indiquant le montant réservé, toute utilisation à la demande et vos dépenses réelles.

## Consulter le tableau de bord Flex {#view-the-flex-dashboard}

Prérequis :

- Vous devez être gestionnaire de compte de facturation.

Pour consulter le tableau de bord Flex :

1. Connectez-vous au [portail clients](https://customers.gitlab.com/).
1. Accédez à la page **Abonnements et achats**.
1. Sur la carte d'abonnement concernée, sélectionnez **Tableau de bord Flex**.

### Afficher l'utilisation quotidienne par fonctionnalité {#view-daily-usage-by-capability}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/customers-gitlab-com/-/merge_requests/16457) dans GitLab 19.2.

{{< /history >}}

La vue d'ensemble du mois comporte un onglet pour chaque capacité de votre réservation, y compris les sièges. Utilisez ces onglets pour voir la quantité de chaque capacité que vous avez consommée chaque jour d'une période de facturation.

Le graphique :

- Affiche l'utilisation cumulée pour chaque jour de la période de facturation.
- Affiche l'utilisation jusqu'à la date du jour pour la période de facturation en cours.
- Affiche l'intégralité de la période de facturation ou seulement les dates auxquelles le prorata s'applique si votre contrat a commencé ou pris fin en cours de période.
- Met en évidence en orange toute utilisation à la demande, y compris les sièges dépassant votre réservation.

Pour afficher l'utilisation quotidienne par fonctionnalité :

1. Ouvrez le tableau de bord Flex.
1. Dans la colonne **Mois**, sélectionnez le mois en cours ou un mois passé.
1. Sélectionnez l'onglet correspondant à la fonctionnalité que vous souhaitez afficher.

### Exporter les données d'utilisation {#export-usage-data}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/customers-gitlab-com/-/work_items/18963) dans GitLab 19.4.

{{< /history >}}

Vous pouvez exporter les données d'utilisation des crédits d'un abonnement pour le mois en cours ou un mois passé.

L'export s'exécute en arrière-plan et GitLab vous envoie par e-mail un lien pour télécharger le résultat. Le lien de téléchargement expire après sept jours.

Le téléchargement est un fichier ZIP contenant deux fichiers CSV :

- Un fichier de résumé quotidien qui liste les événements d'utilisation et les crédits utilisés chaque jour du mois sélectionné.
- Un fichier par événement avec une ligne pour chaque événement facturable, incluant le produit, le type de flow, la session, l'identifiant utilisateur, l'espace de nommage, le projet, les crédits utilisés et le nombre de tokens.

Pour exporter les données d'utilisation :

1. Ouvrez le tableau de bord Flex.
1. Dans la colonne **Mois**, sélectionnez le mois dont vous souhaitez exporter les données.
1. Sélectionnez **Exporter les données d'utilisation**.

## Gestion des réservations {#reservation-management}

Votre réservation correspond à ce que vous vous engagez à consommer pour un seul mois civil. Vous pouvez la modifier pour le mois à venir sans avenant au contrat.

Votre réservation comporte deux parties :

- **Accès à la plateforme** : les sièges que vous réservez pour le mois, au tarif par siège négocié.
- **Extensions** : les crédits que vous réservez pour chaque capacité basée sur des crédits, avec votre remise Flex. Si vous ne réservez aucun crédit pour une capacité, vous payez le tarif catalogue pour ce que vous consommez.

Avant de modifier une réservation, consultez les [conditions applicables](gitlab_flex.md#monthly-reservation-changes), notamment la date limite indiquée dans la colonne **Réserver avant** et la limite de ce que vous pouvez réserver.

### Ajuster votre réservation {#adjust-your-reservation}

Pour ajuster votre réservation pour le mois à venir :

1. Ouvrez le tableau de bord Flex.
1. Dans la colonne **Mois**, sélectionnez le mois avec le statut **À venir**.
1. Sous **Accès à la plateforme**, mettez à jour le nombre de **siège**.
1. Sous **Extensions**, mettez à jour le nombre de **crédits** pour chaque capacité.
1. Sélectionnez **Enregistrer la réservation**.

La page de réservation affiche votre utilisation moyenne pour chaque capacité (lorsqu'elle est disponible), afin que vous puissiez calibrer votre réservation par rapport à ce que vous avez consommé.

Une fois que vous avez enregistré la réservation, un message confirme que la mise à jour a été effectuée. Le tableau de bord Flex affiche les nouveaux montants réservés, qui s'appliquent à partir de ce mois et jusqu'à ce que vous les modifiiez à nouveau.

Vous pouvez mettre à jour votre réservation autant de fois que vous le souhaitez avant la date **Réserver avant**. Seule la valeur enregistrée la plus récente prend effet. Une fois qu'un mois commence, sa réservation est verrouillée.

## Gestion des dépenses {#spend-management}

Par défaut, votre réservation n'est pas une limite de dépenses. L'utilisation au-delà de votre réservation s'accumule en tant qu'utilisation à la demande et est prélevée sur votre solde Flex restant. Pour limiter cela, définissez des contrôles de dépenses et surveillez les notifications d'utilisation.

### Contrôles de dépenses {#spend-controls}

Un contrôle de dépenses limite la quantité qu'une seule capacité peut consommer au-delà de sa réservation, afin qu'une capacité ne puisse pas épuiser votre solde. Les contrôles de dépenses sont définis par capacité, de sorte que limiter une capacité n'affecte pas les autres. Certaines capacités sont toujours actives et ne peuvent pas être plafonnées. Dans la colonne **Contrôle de dépenses**, celles-ci affichent **Illimité** sous forme de texte plutôt que sous forme de liste déroulante, et leur utilisation au-delà de la réservation est facturée au tarif catalogue.

Vous pouvez définir :

- **Restreint** : aucune utilisation à la demande. L'utilisation s'arrête à la réservation et le plafond de dépenses est égal à la réservation.
- **Plafond d'utilisation** : utilisation à la demande limitée. Le plafond de dépenses est égal à la somme du montant de la réservation et du montant plafonné.
- **Illimité** : utilisation à la demande illimitée. Aucun plafond de dépenses.

Par défaut, la liste déroulante **Contrôle de dépenses** pour une capacité est définie sur **Illimité**.

Lorsqu'une capacité atteint sa limite, son utilisation s'arrête. Tout le reste continue de fonctionner. Par exemple, vous pouvez plafonner GitLab Duo Agent Platform et laisser les autres capacités illimitées.

Étant donné que les contrôles de dépenses limitent l'utilisation à la demande, ils ralentissent également la vitesse à laquelle vous consommez votre engagement. Utilisez-les pour les capacités que vous souhaitez contenir, comme les fonctionnalités non critiques ou en version expérimentale.

Contrairement aux sièges et aux crédits, les contrôles de dépenses peuvent être modifiés en cours de mois. Si une capacité a été arrêtée, vous pouvez augmenter ou supprimer son contrôle de dépenses pour reprendre l'utilisation dans le mois en cours.

#### Définir un contrôle de dépenses {#set-a-spend-control}

Vous pouvez définir des contrôles de dépenses pour le mois en cours ou le mois à venir.

Pour définir un contrôle de dépenses pour le mois en cours :

1. Ouvrez le tableau de bord Flex.
1. Dans la colonne **Mois**, sélectionnez le mois avec le statut **Mois en cours**.
1. Sélectionnez **Gérer les contrôles de dépenses**.
1. Sous **Extensions**, dans la ligne de la capacité que vous souhaitez limiter, sélectionnez un type dans la liste déroulante **Contrôle de dépenses**.
1. Si vous avez sélectionné **Plafond d'utilisation**, saisissez le nombre de crédits à autoriser au-delà de la réservation. Ce montant est converti en valeur monétaire au taux de cette capacité.
1. Vérifiez le récapitulatif de la réservation pour confirmer que les contrôles de dépenses sont bien reflétés dans le sous-total et le total de vos extensions.
1. Sélectionnez **Enregistrer**.

Pour définir un contrôle de dépenses pour le mois à venir :

1. Ouvrez le tableau de bord Flex.
1. Dans la colonne **Mois**, sélectionnez le mois avec le statut **À venir**.
1. Sous **Extensions**, dans la ligne de la capacité que vous souhaitez limiter, sélectionnez un type dans la liste déroulante **Contrôle de dépenses**.
1. Si vous avez sélectionné **Plafond d'utilisation**, saisissez le nombre de crédits à autoriser au-delà de la réservation. Ce montant est converti en valeur monétaire au taux de cette capacité.
1. Sélectionnez **Enregistrer la réservation**.

### Notifications d'utilisation {#usage-notifications}

GitLab envoie des e-mails lorsque votre utilisation approche et dépasse vos limites.

GitLab envoie une notification d'utilisation lorsque :

- Une capacité dépasse 50 %, 80 % ou 100 % de sa réservation mensuelle. À 100 %, la capacité commence à utiliser l'usage à la demande.
- Une capacité génère pour la première fois une utilisation à la demande pour le mois. Cette utilisation est prélevée sur votre engagement total au tarif catalogue.
- Une capacité avec un contrôle de dépenses dépasse 50 % ou 80 % de sa limite, ou atteint 100 % et est arrêtée.

### Limites de crédits par utilisateur {#per-user-credit-limits}

Les contrôles de dépenses limitent la consommation pour l'ensemble d'une capacité. Pour limiter le nombre de crédits qu'un utilisateur individuel peut consommer, [configurez des limites de crédits par utilisateur dans GitLab](gitlab_credits_dashboard.md#manage-credit-caps).
