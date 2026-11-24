---
stage: Fulfillment
group: Utilization
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Affichez et gérez votre consommation de crédits.
title: Tableau de bord des GitLab Credits
---

{{< details >}}

- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Introduction dans GitLab 18.7.
- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/21008) du tri des résultats dans GitLab 18.10.

{{< /history >}}

Le tableau de bord des crédits GitLab affiche des informations sur votre utilisation des GitLab Credits. Utilisez le tableau de bord pour surveiller la consommation de crédits, suivre les tendances et identifier les modes d'utilisation.

Pour vous aider à gérer la consommation de crédits, GitLab envoie par e-mail les informations suivantes aux utilisateurs du portail clients liés au compte de facturation :

- Récapitulatifs mensuels de l'utilisation des crédits
- Notifications lorsque les seuils d'utilisation des crédits atteignent 50 %, 80 % et 100 %

Vous pouvez accéder au tableau de bord dans le portail clients et dans GitLab. Sur GitLab Dedicated, le tableau de bord est disponible dans le portail clients et pour les administrateurs d'instance. Les vues d'utilisation des crédits au niveau du groupe et personnelles sont disponibles sur GitLab.com uniquement.

> [!note]
> Les données d'utilisation ne sont pas affichées en temps réel. Les données d'utilisation sont synchronisées régulièrement avec les tableaux de bord ; elles devraient donc apparaître dans les heures qui suivent la consommation effective. Cela signifie que votre tableau de bord affiche l'utilisation récente, mais peut ne pas refléter les actions effectuées au cours des dernières heures.

## Dans le portail clients {#in-customers-portal}

Le tableau de bord des crédits GitLab du portail clients offre la vue la plus détaillée de votre utilisation et de vos coûts.

Dans le tableau de bord, les crédits utilisés correspondent aux crédits retranchés du total disponible. Pour les dépassements (crédits à la demande), les crédits utilisés représentent une utilisation à la demande qui sera payée ultérieurement, si vous avez accepté les conditions de facturation à l'utilisation.

Le tableau de bord affiche des cartes récapitulatives des indicateurs clés :

- Utilisation pour le mois en cours : total des GitLab Credits utilisés pendant le mois en cours (si vous disposez d'un engagement mensuel)
- Crédits inclus : total des crédits inclus dans votre abonnement (si vous disposez d'un engagement mensuel)
- Crédits engagés : Crédits issus de votre pool d'engagements mensuels (le cas échéant)
- Exonérations mensuelles : crédits restants issus des exonérations (le cas échéant)
- Utilisation à la demande : crédits consommés au-delà de vos montants inclus et engagés. Si vous disposez de suffisamment de crédits d'exonération pour compenser tous les crédits à la demande, le tableau de bord GitLab Credits masque la carte **On-Demand** et affiche à la place la carte **Exonération mensuelle**.
- État du contrôle d'utilisation : si certains utilisateurs ont été bloqués et ne peuvent plus accéder à GitLab Duo Agent Platform parce qu'ils ont atteint leur plafond de crédits par utilisateur.

## Dans GitLab {#in-gitlab}

{{< history >}}

- Utilisation de Secrets Manager introduite dans GitLab 19.1.

{{< /history >}}

> [!note]
> Certaines fonctionnalités en prépublication, telles que le Security Review Flow, sont facturables et soumises aux frais de GitLab Credits.

Dans GitLab, le tableau de bord des crédits GitLab permet d'assurer le suivi opérationnel de l'utilisation des crédits dans votre organisation. Utilisez le tableau de bord pour déterminer quels utilisateurs, groupes ou projets génèrent la consommation de crédits et prendre des décisions éclairées sur l'allocation des ressources.

Le tableau de bord affiche les informations suivantes :

- **Utilisation dans l'organisation** : utilisation totale des crédits (facturables et non facturables), utilisateurs actifs, moyenne journalière de crédits et pic d'utilisation quotidienne sur votre instance ou groupe GitLab
- **Utilisation totale des crédits** : utilisation quotidienne de crédits facturables et non facturables pour tous les produits, affichée sous forme de graphique à barres empilées
- **Utilisation par utilisateur** : nombre de crédits utilisés par chaque utilisateur
- **Vue détaillée par utilisateur** : événements d'utilisation individuels pour chaque utilisateur, avec des liens vers les détails de session pour chaque fonctionnalité basée sur les crédits
- **Utilisation par produit** : nombre de crédits utilisés et pourcentage du total des crédits pour les fonctionnalités basées sur les crédits

> [!note]
> Tant que [GitLab Secrets Manager](../ci/secrets/secrets_manager/_index.md) est en version bêta, GitLab ne facture pas son utilisation. Secrets Manager apparaît dans le tableau de bord des crédits GitLab, mais n'affiche aucune donnée d'utilisation jusqu'à la fin de sa version bêta.

### Utilisation non facturable {#non-billable-usage}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/23876) dans GitLab 19.5.

{{< /history >}}

L'utilisation non facturable est une consommation de crédits que GitLab ne facture pas. Le graphique **Utilisation totale des crédits** affiche :

- **Facturable** : nombre de crédits facturables utilisés
- **Non facturable** : nombre de crédits non facturables utilisés, affiché uniquement lorsque la période sélectionnée inclut une utilisation non facturable
- **Barres empilées** : crédits utilisés quotidiennement, avec les raisons d'**Utilisation facturable** et d'**Utilisation non facturable** comme séries distinctes

Le graphique affiche les séries d'utilisation non facturable suivantes :

| Série | Description |
|--------|-------------|
| **Utilisation non facturable (Promotionnelle)** | Utilisation couverte par une promotion. |
| **Utilisation non facturable (Bêta)** | Utilisation d'une fonctionnalité qui n'est pas encore facturable. |
| **Utilisation non facturable (Autre)** | Utilisation qui n'a pas été facturée pour une autre raison. |

Le graphique affiche uniquement les raisons de l'utilisation dans la période sélectionnée. Si les données d'utilisation non facturable sont temporairement indisponibles, le graphique affiche uniquement l'utilisation facturable.

## Afficher le tableau de bord des crédits GitLab {#view-the-gitlab-credits-dashboard}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/customers-gitlab-com/-/work_items/15910) de la sélection d'une période dans l'historique d'utilisation dans GitLab 18.11.

{{< /history >}}

{{< tabs >}}

{{< tab title="Portail clients" >}}

Prérequis :

- Pour afficher des informations détaillées sur l'utilisation, vous devez être gestionnaire du compte de facturation.

1. Connectez-vous au [portail clients](https://customers.gitlab.com/).
1. Sur la carte d'abonnement, sélectionnez **Tableau de bord des crédits GitLab**.
1. Facultatif. Pour afficher un mois précédent, dans la liste déroulante **Période d'utilisation**, sélectionnez la période que vous souhaitez consulter.
1. Facultatif. Pour trier les résultats par **Utilisateur** ou par **Crédits totaux utilisés**, sélectionnez la colonne correspondante.

{{< /tab >}}

{{< tab title="GitLab.com" >}}

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Sélectionnez **Paramètres** > **GitLab Credits**.
1. Facultatif. Pour trier les résultats par **Utilisateur** ou par **Crédits totaux utilisés**, sélectionnez la colonne correspondante.

{{< /tab >}}

{{< tab title="GitLab Self-Managed" >}}

Prérequis :

- Vous devez être administrateur.
- Votre instance doit pouvoir synchroniser les données de votre abonnement avec GitLab.

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Credits**.
1. Facultatif. Pour trier les résultats par **Utilisateur** ou par **Crédits totaux utilisés**, sélectionnez la colonne correspondante.

{{< /tab >}}

{{< /tabs >}}

Par défaut, les données par utilisateur ne sont pas affichées dans le tableau de bord des crédits GitLab. Pour les afficher, vous devez activer ce paramètre pour votre [groupe](../user/group/manage.md#display-gitlab-credits-user-data) ou votre [instance](../administration/settings/visibility_and_access_controls.md#display-gitlab-credits-user-data).

## Utilisation par les sujets non humains {#non-human-subject-usage}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/596238) dans GitLab 19.0.

{{< /history >}}

La consommation de crédits peut être déclenchée par un utilisateur humain ou un sujet non humain (par exemple, une fonctionnalité d'IA comme le flow SAST False Positive Detection).

Pour vous aider à identifier où les crédits sont consommés, l'onglet **Utilisation par utilisateur** du tableau de bord des crédits GitLab affiche un badge **Flow automatisé** à côté des lignes représentant des sujets non humains. Les lignes sans badge représentent des utilisateurs humains.

L'affichage du badge **Flow automatisé** est contrôlé par le paramètre **Afficher les données utilisateur de GitLab Credits**, disponible pour les [groupes](../user/group/manage.md#display-gitlab-credits-user-data) et les [instances](../administration/settings/visibility_and_access_controls.md#display-gitlab-credits-user-data).

## Plafonds d'utilisation {#usage-caps}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/19881) dans GitLab 18.11 [avec le feature flag](../administration/feature_flags/_index.md) `budget_caps_graphql_api`. Activés par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/607551) dans GitLab 19.3. Le feature flag `budget_caps_graphql_api` a été supprimé.

{{< /history >}}

Vous pouvez définir un plafond mensuel de GitLab Credits aux niveaux de l'abonnement et de l'utilisateur pour éviter des frais de dépassement imprévus. Lorsque la consommation de crédits atteint le plafond configuré, l'accès aux fonctionnalités basées sur les crédits est automatiquement suspendu jusqu'au début de la prochaine période de facturation ou jusqu'à ce qu'un administrateur ajuste ou désactive le plafond.

Les types de plafond suivants sont disponibles :

| Type de plafond | S'applique à | Sources de crédits comptabilisées | Géré via |
|---|---|---|---|
| Plafond de l'abonnement | Tous les utilisateurs de l'abonnement | À la demande uniquement | Portail clients |
| Plafond utilisateur fixe | Chaque utilisateur (limite par défaut) | Tous, pour l'utilisation par un sujet humain | Interface utilisateur, API GraphQL |
| Remplacement par utilisateur | Utilisation totale d'un utilisateur donné, y compris ses crédits inclus. Se substitue au plafond fixe. Un utilisateur peut donc consommer des crédits à hauteur de la plus élevée des deux valeurs : son allocation de crédits inclus ou son plafond. | Tous, pour l'utilisation par un sujet humain | Interface utilisateur, API GraphQL |

Lorsque l'utilisation à la demande dans la période de facturation en cours atteint ou dépasse le plafond configuré, toutes les fonctionnalités basées sur les crédits sont suspendues pour tous les utilisateurs de cet abonnement ou de cette instance, et GitLab envoie une notification par e-mail aux gestionnaires de compte de facturation. Pour les plafonds définis au niveau de l'utilisateur, seul l'utilisateur qui a atteint son plafond voit son accès suspendu.

Les plafonds utilisateur fixes et les plafonds de dérogation par utilisateur s'appliquent à la consommation qui dépasse l'allocation de crédits inclus de l'utilisateur. Tant qu'un utilisateur dispose encore de crédits inclus, il peut continuer à les consommer même après que son utilisation a atteint le plafond. Le plafond ne prend effet qu'après épuisement des crédits inclus de l'utilisateur.

Les utilisateurs qui ont atteint leur plafond ne peuvent plus accéder aux fonctionnalités de GitLab Duo Agent Platform jusqu'à ce que le plafond soit relevé ou que commence la période de facturation suivante.

Les compteurs d'utilisation sont automatiquement réinitialisés au début de chaque période de facturation. Les valeurs des plafonds restent inchangées d'une période de facturation à l'autre, sauf modification.

Les plafonds sont appliqués à partir des données d'utilisation disponibles les plus récentes. Comme les données ne sont pas disponibles en temps réel, une utilisation supplémentaire limitée de GitLab Credits peut se produire avant que le plafond ne soit appliqué.

Les plafonds n'empêchent pas les utilisateurs de consommer leurs GitLab Credits inclus. Le plafond ne s'applique à chaque utilisateur qu'après épuisement de son allocation incluse. Jusque-là, l'utilisateur conserve un accès complet à GitLab Duo Agent Platform, quelle que soit la valeur du plafond, y compris lorsque celui-ci est fixé à `0`.

Pour arrêter immédiatement toute consommation de GitLab Credits, quelle que soit la balance des crédits inclus, [retirez le siège GitLab Duo](subscription-add-ons.md#assign-and-remove-gitlab-duo-seats-in-bulk) aux utilisateurs concernés ou [désactivez GitLab Duo](../user/gitlab_duo/turn_on_off.md#turn-gitlab-duo-on-or-off) pour l'espace de nommage. Pour automatiser la suppression et la réaffectation des sièges, utilisez les mutations GraphQL [`userAddOnAssignmentRemove`](../api/graphql/reference/_index.md#mutationuseraddonassignmentremove) et [`userAddOnAssignmentCreate`](../api/graphql/reference/_index.md#mutationuseraddonassignmentcreate).

La manière dont la valeur du plafond est appliquée dépend ensuite du type de plafond :

- Un **plafond au niveau de l'abonnement** s'applique uniquement à l'utilisation à la demande. Le plafond correspond au volume d'utilisation à la demande autorisé pour l'ensemble de l'abonnement, en plus des crédits inclus dont dispose chaque utilisateur.
- Un **plafond par utilisateur** s'applique à l'utilisation totale d'un utilisateur, y compris ses crédits inclus, pour l'utilisation que l'utilisateur déclenche directement. Un utilisateur peut donc consommer des crédits à hauteur de la plus élevée des deux valeurs : son allocation de crédits inclus ou son plafond.

> [!note]
> L'utilisation des [flows GitLab Duo Agent Platform](../user/duo_agent_platform/_index.md) exécutés sous un compte de service est facturée à l'espace de nommage, et non à l'utilisateur, et n'est pas comptabilisée dans le plafond fixe ou le plafond de substitution par utilisateur. Cette utilisation peut toujours apparaître dans la colonne **Crédits totaux utilisés** de l'utilisateur, de sorte que son utilisation affichée peut dépasser son plafond sans que l'utilisateur soit bloqué. Pour limiter cette utilisation, définissez un plafond au niveau de l'abonnement ou retirez le siège GitLab Duo de l'utilisateur.

Pour contrôler qui peut utiliser GitLab Duo Agent Platform, [restreignez l'accès à GitLab Duo](../administration/gitlab_duo/configure/access_control.md#restrict-access-to-gitlab-duo) en fonction de l'appartenance au groupe. Les contrôles d'accès modifient l'accès aux fonctionnalités, pas la consommation de crédits, et ne définissent pas de plafond de crédits au niveau du groupe.

### Exemples {#examples}

Pour un plafond au niveau de l'abonnement, prenons l'exemple d'un abonnement qui compte 10 utilisateurs disposant chacun de 100 GitLab Credits inclus. Le gestionnaire du compte de facturation fixe à `0` le plafond d'utilisation à la demande au niveau de l'abonnement.

- Un utilisateur qui a déjà utilisé la totalité de ses 100 crédits inclus ne peut plus accéder aux fonctionnalités de GitLab Duo Agent Platform dès le contrôle d'application suivant, car toute utilisation supplémentaire serait à la demande.
- Un utilisateur qui n'a utilisé que 40 de ses crédits inclus peut continuer à utiliser les fonctionnalités de GitLab Duo Agent Platform et consommer les 60 crédits inclus restants. Le plafond `0` ne s'applique pas encore à cet utilisateur.

Pour un plafond par utilisateur, prenons l'exemple d'un utilisateur qui dispose de 24 GitLab Credits inclus.

- Avec un plafond par utilisateur de `50`, l'utilisateur est bloqué après avoir consommé 50 crédits au total, soit 26 crédits au-delà de son allocation incluse.
- Avec un plafond par utilisateur de `10`, l'utilisateur est bloqué après avoir consommé 24 crédits, une fois son allocation incluse épuisée.

### Définir un plafond d'utilisation au niveau de l'abonnement {#set-a-subscription-level-usage-cap}

Prérequis :

- Vous devez être gestionnaire de compte de facturation.

1. Connectez-vous au [portail clients](https://customers.gitlab.com/).
1. Sur la carte d'abonnement, sélectionnez **Tableau de bord des crédits GitLab**.
1. Sélectionnez **Contrôles des dépenses**.
1. Dans le panneau **Plafond de crédits à la demande**, activez le bouton bascule **Définir un plafond de crédits à la demande**.
1. Saisissez le nombre maximal autorisé de GitLab Credits à la demande par période de facturation.
1. Sélectionnez **Enregistrer les modifications**.

Si le plafond est fixé à une valeur inférieure à la consommation totale à la demande actuellement indiquée pour la période de facturation en cours, il est considéré comme atteint dès le prochain contrôle d'application.

Pour désactiver le plafond, désactivez le bouton à bascule **Définir un plafond de crédits à la demande**. Lorsque cette option est désactivée, aucun plafond de GitLab Credits à la demande ne s'applique au niveau de l'abonnement et la facturation reprend son fonctionnement antérieur.

Vous pouvez utiliser l'API GraphQL pour [consulter les plafonds d'utilisation](../api/graphql/reference/_index.md#gitlabsubscriptionbudgetcaps) et définir un [plafond utilisateur fixe](../api/graphql/reference/_index.md#mutationupsertflatusercap) ou un [plafond de substitution par utilisateur](../api/graphql/reference/_index.md#mutationupsertuserbudgetcapoverrides).

### Gérer les plafonds de crédits {#manage-credit-caps}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/628559) dans GitLab 19.4 [avec un feature flag](../administration/feature_flags/_index.md) nommé `credit_caps_ui`. Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Pour gérer les plafonds de crédits :

{{< tabs >}}

{{< tab title="GitLab.com" >}}

Prérequis :

- Le rôle Propriétaire pour le groupe.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Sélectionnez **Paramètres** > **GitLab Credits**.
1. Sélectionnez **Plafonds de crédit**.

{{< /tab >}}

{{< tab title="GitLab Self-Managed" >}}

Prérequis :

- Disposer d'un accès administrateur.

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Credits**.
1. Sélectionnez **Plafonds de crédit**.

{{< /tab >}}

{{< /tabs >}}

Sur la page **Plafonds de crédit**, vous pouvez définir les éléments suivants :

- **Plafond fixe par utilisateur** : un plafond de crédit par défaut pour tous les utilisateurs de l'abonnement.
- **Substitutions de plafond par utilisateur** : un plafond spécifique pour les utilisateurs individuels qui remplace le plafond fixe par utilisateur.

#### Définir un plafond fixe par utilisateur {#set-a-flat-user-cap}

Pour définir un plafond fixe par utilisateur s'appliquant à tous les utilisateurs par défaut :

1. Saisissez le nombre maximum de GitLab Credits qu'un utilisateur peut consommer par période de facturation.
1. Activez le bouton bascule pour activer l'application du plafond.
1. Sélectionnez **Enregistrer**.

#### Définir des substitutions de plafond par utilisateur {#set-per-user-cap-overrides}

Vous pouvez ajouter, mettre à jour et désactiver des substitutions de plafond pour les utilisateurs individuels.

Pour ajouter une substitution :

1. Sélectionnez **Ajouter une substitution**.
1. Sélectionnez un ou plusieurs utilisateurs.
1. Définissez la valeur du plafond et activez ou désactivez le bouton bascule **Activé**.
1. Sélectionnez **Enregistrer**.

Pour mettre à jour une substitution :

1. Sous **Substitutions de plafond par utilisateur**, ajustez la valeur du plafond pour l'utilisateur et activez ou désactivez le bouton bascule **Activé**.
1. Sélectionnez **Enregistrer**.

Pour désactiver une substitution :

1. Sous **Substitutions de plafond par utilisateur**, désactivez le bouton bascule **Activé** pour l'utilisateur.
1. Sélectionnez **Enregistrer**.

#### Mise à jour en bloc des substitutions {#bulk-update-overrides}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257651) dans GitLab 19.5 [avec un feature flag](../administration/feature_flags/_index.md) nommé `credit_caps_bulk_update`. Activés par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Utilisez les mises à jour en bloc pour ajouter ou modifier des substitutions pour de nombreux utilisateurs à la fois.

Vous pouvez coller une liste CSV d'utilisateurs, qui est fusionnée dans la liste existante de substitutions en ajoutant de nouveaux enregistrements ou en mettant à jour les enregistrements existants.

L'entrée accepte trois colonnes, séparées par des virgules :

| Colonne | Type | Valeurs acceptées |
|--------|------|-----------------|
| `username` | Chaîne | Nom d'utilisateur GitLab sans le préfixe `@` (par exemple, `jsmith`, et non `@jsmith`) |
| `cap` | Nombre | Nombre non négatif. Utilisez `.` comme séparateur décimal pour les valeurs fractionnaires (par exemple, `0`, `500`, `1000.5`). |
| `enabled` | Booléen | `true`, `True`, `TRUE`, `false`, `False`, `FALSE` |

Vous pouvez ajouter une ligne d'en-tête facultative sur la première ligne. La ligne d'en-tête doit être `username,cap,enabled` et n'est pas sensible à la casse. Si une validation échoue ou qu'un nom d'utilisateur est introuvable, la totalité de la mise à jour est rejetée et aucune modification n'est enregistrée.

Exemple avec une ligne d'en-tête :

```plaintext
username,cap,enabled
sidney.jones,500,true
zhang.wei,1000.5,True
alex.garcia,250,false
```

Exemple sans ligne d'en-tête :

```plaintext
sidney.jones,500,true
zhang.wei,1000.5,True
alex.garcia,250,false
```

Pour effectuer une mise à jour en bloc des substitutions de plafond par utilisateur :

1. Sous **Substitutions de plafond par utilisateur**, sélectionnez **Mise à jour en bloc**.
1. Dans la fenêtre modale, collez une liste CSV.
1. Sélectionnez **Enregistrer**.

## État du contrôle d'utilisation {#usage-control-status}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/594635) dans GitLab 18.11.

{{< /history >}}

Lorsque les plafonds de crédits par utilisateur sont activés, l'onglet **Utilisation par l'utilisateur/utilisatrice** du tableau de bord des crédits GitLab affiche la colonne **État du contrôle d'utilisation**. Cette colonne indique si chaque utilisateur peut accéder aux fonctionnalités basées sur les crédits ou s'il est bloqué parce qu'il a atteint son plafond de crédits.

La colonne **État du contrôle d'utilisation** affiche le statut **Utilisation bloquée** uniquement lorsque GitLab applique le plafond à l'utilisateur. GitLab applique le plafond une fois les crédits inclus de l'utilisateur épuisés. Un utilisateur qui a atteint son plafond mais qui dispose encore de crédits inclus a le statut **Utilisation régulière**, car il peut continuer à consommer ses crédits inclus.

La colonne affiche l'un des statuts suivants :

| Statut | Description |
|--------|-------------|
| **Utilisation régulière** | L'utilisateur n'a pas atteint son plafond de crédits ou l'a atteint mais dispose encore de crédits inclus, et peut utiliser les fonctionnalités de GitLab Duo Agent Platform. |
| **Utilisation bloquée** | L'utilisateur a épuisé ses crédits inclus et atteint son plafond par utilisateur. Le plafond est soit le plafond fixe par utilisateur défini pour tous les utilisateurs de l'abonnement, soit un plafond de substitution par utilisateur défini spécifiquement pour eux. |

Le tableau de bord n'indique pas quel type de plafond a bloqué un utilisateur. Pour déterminer le type de plafond, utilisez l'[API GraphQL](../api/graphql/reference/_index.md#gitlabsubscriptionusageblockedstatus).

La colonne **État du contrôle d'utilisation** affiche uniquement les plafonds par utilisateur. Le plafond à la demande au niveau de l'abonnement s'applique à l'ensemble de l'abonnement, et non aux utilisateurs individuels, et n'est pas répertorié dans cette colonne.

Le statut reflète uniquement l'utilisation que l'utilisateur déclenche directement. Les lignes portant le badge **Flux automatisé** représentent des sujets non humains et n'affichent jamais **Utilisation bloquée**, car les plafonds par utilisateur ne leur sont pas applicables.

### Débloquer un utilisateur ayant atteint son plafond de crédits {#unblock-a-user-who-reached-their-credit-cap}

Vous pouvez restaurer l'accès d'un utilisateur bloqué en utilisant l'API GraphQL de remplacement par utilisateur.

Pour débloquer un utilisateur, vous pouvez :

- Augmenter le plafond : définir un plafond de remplacement par utilisateur plus élevé afin que son utilisation soit inférieure à la nouvelle limite.
- Supprimer le plafond : supprimer le remplacement par utilisateur afin que l'utilisateur ne soit plus soumis à un plafond individuel.

Une fois le plafond mis à jour, le statut de l'utilisateur passe à **Utilisation régulière** et il peut à nouveau utiliser les fonctionnalités basées sur les crédits.

## Afficher les détails d'utilisation des crédits d'un utilisateur {#view-user-credit-usage-details}

{{< history >}}

- Lien vers les détails de session de GitLab Duo Agent Platform [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/579139) dans GitLab 18.10.

{{< /history >}}

Pour afficher les événements d'utilisation individuels d'un utilisateur dans une vue détaillée :

1. Dans le tableau de bord des crédits GitLab, sélectionnez l'onglet **Utilisation par utilisateur**.
1. Dans la colonne **Utilisateur**, sélectionnez l'utilisateur que vous souhaitez consulter.
1. Pour afficher les détails de session, dans la colonne **Action**, sélectionnez l'action que vous souhaitez consulter.

> [!note]
> Les liens de session sont disponibles uniquement pour les événements d'utilisation de GitLab Duo Agent Platform déclenchés dans un projet et ayant un identifiant de session associé. Les événements d'utilisation déclenchés au sein d'un groupe, les événements hérités et les actions effectuées en dehors de GitLab Duo Agent Platform ne comportent pas de liens.

## Exporter les données d'utilisation {#export-usage-data}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/customers-gitlab-com/-/work_items/14504) dans GitLab 18.10.
- Export en arrière-plan avec un fichier de détails par événement [introduit](https://gitlab.com/gitlab-org/customers-gitlab-com/-/work_items/18963) dans GitLab 19.4.

{{< /history >}}

Vous pouvez exporter les données d'utilisation des crédits d'un abonnement dans le portail clients. L'export s'exécute en arrière-plan et GitLab vous envoie par e-mail un lien pour télécharger le résultat. Le lien de téléchargement expire après sept jours.

Le téléchargement est un fichier ZIP contenant deux fichiers CSV :

- Un fichier de résumé quotidien qui répertorie les événements d'utilisation et les crédits utilisés chaque jour de la période sélectionnée.
- Un fichier par événement avec une ligne pour chaque événement facturable, incluant le produit, le type de flow, la session, l'identifiant utilisateur, l'espace de nommage, le projet, les crédits utilisés et le nombre de tokens.

Chaque export couvre une période allant jusqu'à 31 jours.

Prérequis :

- Vous devez être gestionnaire de compte de facturation.

1. Connectez-vous au [portail clients](https://customers.gitlab.com/).
1. Sur la carte d'abonnement, sélectionnez **Tableau de bord des crédits GitLab**.
1. Dans la liste déroulante **Période d'utilisation**, sélectionnez la période pour laquelle vous souhaitez exporter les données.
1. Sélectionnez **Exporter les données d'utilisation**.

## Afficher votre utilisation de GitLab Credits {#view-your-gitlab-credits-usage}

{{< details >}}

- Offre : GitLab.com

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/22817) dans GitLab 19.5.

{{< /history >}}

Vous pouvez suivre les GitLab Credits que vous consommez dans un groupe principal sur la page **Utilisation de vos crédits GitLab**. Le tableau de bord ne rend compte que de la consommation de crédits. Il n'affiche pas vos crédits restants ni de plafond de crédits.

**Utilisation de vos crédits GitLab** affiche :

- Votre utilisation pour la période de facturation en cours.
- Un graphique de votre consommation quotidienne de crédits pour l'intervalle de dates et les produits sélectionnés.
- **Utilisation totale** : nombre total de crédits utilisés dans l'intervalle de dates et les produits sélectionnés.
- **Utilisation quotidienne moyenne** : nombre moyen de crédits utilisés par jour pour l'intervalle de dates et les produits sélectionnés.
- **Pic d'utilisation quotidienne** : le nombre le plus élevé de crédits consommés en un seul jour pour l'intervalle de dates et les produits sélectionnés.

Prérequis :

- Vous devez être membre d'un groupe principal disposant d'un abonnement qui inclut des GitLab Credits.

Pour afficher votre utilisation de GitLab Credits :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Credits**.
1. Si vous êtes membre de plusieurs groupes, dans la liste déroulante **Groupe**, sélectionnez un groupe principal.
1. Facultatif. Dans la liste déroulante **Plage de dates**, sélectionnez l'intervalle de dates pour lequel vous souhaitez afficher votre utilisation. La valeur par défaut est le mois en cours.
1. Facultatif. Dans la liste déroulante **Produits**, sélectionnez les produits que vous souhaitez inclure.
