---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: "Configurer le Service d'assistance"
description: "Activez le Service d'assistance pour un projet et configurez la visibilité des tickets, les modèles d'e-mail, les adresses e-mail personnalisées et l'ingestion d'e-mails multi-nœuds."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

Par défaut, le Service d'assistance est actif dans les nouveaux projets. S'il n'est pas actif, vous pouvez l'activer dans les paramètres du projet.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.
- Sur GitLab Self-Managed, vous devez [configurer les e-mails entrants](../../../administration/incoming_email.md#set-it-up) pour l'instance GitLab. Vous devriez utiliser le [sous-adressage d'e-mail](../../../administration/incoming_email.md#email-sub-addressing), mais vous pouvez également utiliser les [boîtes de réception fourre-tout](../../../administration/incoming_email.md#catch-all-mailbox). Pour ce faire, vous devez disposer d'un accès administrateur. Sans e-mail entrant prenant en charge le sous-adressage ou une boîte de réception fourre-tout, la section **Service d'assistance** ne s'affiche pas dans les paramètres du projet.
- Vous devez avoir activé le [suivi des tickets](../settings/_index.md#configure-project-features-and-permissions) pour le projet.

Pour activer le Service d'assistance dans votre projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Service d'assistance**.
1. Activez le bouton **Activer le Service d'assistance**.
1. Facultatif. Remplissez les champs.
   - [Ajoutez un suffixe](#configure-a-suffix-for-service-desk-alias-email) à votre adresse e-mail du Service d'assistance.
   - Si la liste sous **Modèle à ajouter à tous les tickets du Service Desk** est vide, créez un [modèle de description](../description_templates.md) dans votre dépôt.
1. Sélectionnez **Enregistrer les modifications**.

Le Service d'assistance est maintenant activé pour ce projet. Si quelqu'un envoie un e-mail à l'adresse disponible sous **Adresse de courriel à utiliser pour le Service Desk**, GitLab crée un ticket confidentiel avec le contenu de l'e-mail.

## Glossaire du Service d'assistance {#service-desk-glossary}

Ce glossaire fournit des définitions pour les termes liés au Service d'assistance.

| Terme                                             | Définition |
|--------------------------------------------------|------------|
| [Participant externe](external_participants.md) | Utilisateurs sans compte GitLab pouvant interagir avec un ticket ou un ticket du Service d'assistance uniquement par e-mail. |
| Demandeur                                        | Participant externe qui a créé le ticket du Service d'assistance ou a été ajouté comme demandeur à l'aide de l'[action rapide `/convert_to_ticket`](using_service_desk.md#create-a-service-desk-ticket-in-gitlab-ui). |

## Améliorer la sécurité de votre projet {#improve-your-projects-security}

Pour améliorer la sécurité de votre projet de Service d'assistance, vous devriez :

- Placer l'adresse e-mail du Service d'assistance derrière un alias sur votre système de messagerie afin de pouvoir la modifier ultérieurement.
- [Activer Akismet](../../../integration/akismet.md) sur votre instance GitLab pour ajouter une vérification anti-spam à ce service. Les e-mails spam non bloqués peuvent entraîner la création de nombreux tickets indésirables.

## Personnaliser les e-mails envoyés aux participants externes {#customize-emails-sent-to-external-participants}

{{< history >}}

- Restriction des modèles personnalisés pour les nouveaux espaces de nommage GitLab.com sur les forfaits Gratuit et d'essai [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254265) dans GitLab 19.4 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `service_desk_restrict_custom_templates`. Fonctionnalité désactivée par défaut. S'applique aux espaces de nommage créés à partir du 10 septembre 2026.

{{< /history >}}

Un e-mail est envoyé aux participants externes dans les cas suivants :

- Un demandeur soumet un nouveau ticket en envoyant un e-mail au Service d'assistance.
- Un participant externe est ajouté à un ticket du Service d'assistance.
- Un nouveau commentaire public est ajouté à un ticket du Service d'assistance.
  - La modification d'un commentaire ne déclenche pas l'envoi d'un nouvel e-mail.

Vous pouvez personnaliser le corps de ces e-mails avec des modèles d'e-mail du Service d'assistance. Les modèles peuvent inclure du [Markdown GitLab](../../markdown.md) et [certaines balises HTML](../../markdown.md#inline-html). Par exemple, vous pouvez formater les e-mails pour inclure un en-tête et un pied de page conformément aux directives de marque de votre organisation. Vous pouvez également inclure les espaces réservés suivants pour afficher du contenu dynamique spécifique au ticket du Service d'assistance ou à votre instance GitLab.

> [!note]
> Sur GitLab.com, les espaces de nommage de niveau supérieur créés à partir du 10 septembre 2026 ne peuvent pas utiliser de modèles d'e-mail personnalisés du Service d'assistance lorsque l'espace de nommage est sur un forfait Gratuit ou un forfait d'essai. Ces espaces de nommage utilisent à la place les modèles d'e-mail GitLab par défaut. Les e-mails sont toujours envoyés et les tickets, commentaires et participants continuent de fonctionner normalement. Les espaces de nommage créés avant le 10 septembre 2026 ne sont pas affectés, quel que soit le forfait. Pour les groupes, vous pouvez utiliser des modèles personnalisés après avoir souscrit à un forfait payant et non d'essai (GitLab Premium, GitLab Ultimate ou Open Source). Les espaces de nommage personnels ne peuvent pas souscrire à un abonnement sur GitLab.com ; ainsi, un espace de nommage personnel créé à cette date ou après ne peut pas utiliser de modèles personnalisés. GitLab Self-Managed n'est pas affecté.

| Espace réservé            | `thank_you.md` et `new_participant` | `new_note.md`          | Description |
|------------------------|--------------------------------------|------------------------|-------------|
| `%{ISSUE_ID}`          | {{< yes >}}               | {{< yes >}} | IID du ticket. |
| `%{ISSUE_PATH}`        | {{< yes >}}               | {{< yes >}} | Chemin du projet suivi de l'IID du ticket. |
| `%{ISSUE_URL}`         | {{< yes >}}               | {{< yes >}} | URL du ticket. Les participants externes ne peuvent consulter le ticket que si le projet est public et que le ticket n'est pas confidentiel (les tickets du Service d'assistance sont confidentiels par défaut). |
| `%{ISSUE_DESCRIPTION}` | {{< yes >}}               | {{< yes >}} | Description du ticket. Si un utilisateur a modifié la description, celle-ci peut contenir des informations sensibles qui ne sont pas destinées à être communiquées aux participants externes. Utilisez cet espace réservé avec précaution et idéalement uniquement si vous ne modifiez jamais les descriptions de tickets ou si votre équipe est informée de la conception du modèle. |
| `%{UNSUBSCRIBE_URL}`   | {{< yes >}}               | {{< yes >}} | URL de désabonnement. Découvrez comment [vous désabonner en tant que participant externe](external_participants.md#unsubscribing-from-notification-emails) et [utiliser les en-têtes de désabonnement dans les e-mails de notification de GitLab](../../profile/notifications.md#using-an-email-client-or-other-software). |
| `%{NOTE_TEXT}`         | {{< no >}}                | {{< yes >}} | Le nouveau commentaire ajouté au ticket par un utilisateur. Veillez à inclure cet espace réservé dans `new_note.md`. Sinon, les participants externes risquent de ne jamais voir les mises à jour de leur ticket du Service d'assistance. |

### E-mail de remerciement {#thank-you-email}

Lorsqu'un demandeur soumet un ticket via le Service d'assistance, GitLab envoie un **e-mail de remerciement**. Sans configuration supplémentaire, GitLab envoie l'e-mail de remerciement par défaut.

Pour créer un modèle d'e-mail de remerciement personnalisé :

1. Dans le répertoire `.gitlab/service_desk_templates/` de votre dépôt, créez un fichier nommé `thank_you.md`.
1. Remplissez le fichier Markdown avec du texte, du [Markdown GitLab](../../markdown.md), [certaines balises HTML sélectionnées](../../markdown.md#inline-html) et des espaces réservés pour personnaliser la réponse aux demandeurs du Service d'assistance.

### E-mail de nouveau participant {#new-participant-email}

{{< history >}}

- E-mail `new_participant` [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/299261) dans GitLab 17.0.

{{< /history >}}

Lorsqu'un [participant externe](external_participants.md) est ajouté au ticket, GitLab envoie un **e-mail de nouveau participant** pour l'informer qu'il fait partie de la conversation. Sans configuration supplémentaire, GitLab envoie l'e-mail de nouveau participant par défaut.

Pour créer un modèle d'e-mail de nouveau participant personnalisé :

1. Dans le répertoire `.gitlab/service_desk_templates/` de votre dépôt, créez un fichier nommé `new_participant.md`.
1. Remplissez le fichier Markdown avec du texte, du [Markdown GitLab](../../markdown.md), [certaines balises HTML sélectionnées](../../markdown.md#inline-html) et des espaces réservés pour personnaliser la réponse aux demandeurs du Service d'assistance.

### E-mail de nouvelle note {#new-note-email}

Lorsqu'un ticket du Service d'assistance reçoit un nouveau commentaire public, GitLab envoie un **e-mail de nouvelle note**. Sans configuration supplémentaire, GitLab envoie le contenu du commentaire.

Pour conserver l'identité visuelle de votre marque dans vos e-mails, vous pouvez créer un modèle d'e-mail de nouvelle note personnalisé. Pour ce faire :

1. Dans le répertoire `.gitlab/service_desk_templates/` de votre dépôt, créez un fichier nommé `new_note.md`.
1. Remplissez le fichier Markdown avec du texte, du [Markdown GitLab](../../markdown.md), [certaines balises HTML sélectionnées](../../markdown.md#inline-html) et des espaces réservés pour personnaliser l'e-mail de nouvelle note. Assurez-vous d'inclure `%{NOTE_TEXT}` dans le modèle pour que le destinataire de l'e-mail puisse lire le contenu du commentaire.

### En-tête, pied de page et texte supplémentaire à l'échelle de l'instance {#instance-wide-email-header-footer-and-additional-text}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Les administrateurs d'instance peuvent ajouter un en-tête, un pied de page ou du texte supplémentaire à l'instance GitLab et les appliquer à tous les e-mails envoyés depuis GitLab. Si vous utilisez un `thank_you.md`, un `new_participant.md` ou un `new_note.md` personnalisé, pour inclure ce contenu, ajoutez `%{SYSTEM_HEADER}`, `%{SYSTEM_FOOTER}` ou `%{ADDITIONAL_TEXT}` à vos modèles.

Pour plus d'informations, consultez les [messages d'en-tête et de pied de page système](../../../administration/appearance.md#add-system-header-and-footer-messages) et le [texte supplémentaire personnalisé](../../../administration/settings/email.md#custom-additional-text).

## Utiliser un modèle personnalisé pour les tickets du Service d'assistance {#use-a-custom-template-for-service-desk-tickets}

Vous pouvez sélectionner un [modèle de description](../description_templates.md#create-a-description-template) par projet à ajouter à la description de chaque nouveau ticket du Service d'assistance.

Vous pouvez définir des modèles de description à différents niveaux :

- L'ensemble de l'[instance](../description_templates.md#set-instance-level-description-templates).
- Un [groupe ou sous-groupe](../description_templates.md#set-group-level-description-templates) spécifique.
- Un [projet](../description_templates.md#set-a-default-template-for-merge-requests-and-issues) spécifique.

Les modèles sont hérités. Par exemple, dans un projet, vous pouvez également accéder aux modèles définis pour l'instance ou les groupes parents du projet.

Prérequis :

- Vous devez avoir [créé un modèle de description](../description_templates.md#create-a-description-template).

Pour utiliser un modèle de description personnalisé avec le Service d'assistance :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Service d'assistance**.
1. Dans la liste déroulante **Modèle à ajouter à tous les tickets du Service Desk**, recherchez ou sélectionnez votre modèle.

## Utilisateur Support Bot {#support-bot-user}

En coulisses, le Service d'assistance fonctionne grâce à l'utilisateur spécial Support Bot qui crée les tickets. Cet utilisateur n'est pas un [utilisateur facturable](../../../subscriptions/manage_seats.md#criteria-for-non-billable-users) et n'est donc pas comptabilisé dans la limite de licences.

Les commentaires générés à partir des e-mails du Service d'assistance affichent l'adresse e-mail de l'utilisateur qui a envoyé l'e-mail.

### Modifier le nom d'affichage du Support Bot {#change-the-support-bots-display-name}

Vous pouvez modifier le nom d'affichage de l'utilisateur Support Bot. Les e-mails envoyés depuis les tickets du Service d'assistance comportent ce nom dans l'en-tête `From`. Le nom d'affichage par défaut est `GitLab Support Bot`.

Pour modifier le nom d'affichage de l'e-mail personnalisé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Service d'assistance**.
1. Sous **Nom à afficher pour le courriel**, saisissez un nouveau nom.
1. Sélectionnez **Enregistrer les modifications**.

## Visibilité des tickets par défaut {#default-ticket-visibility}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/33091) dans GitLab 17.2.

{{< /history >}}

Les nouveaux tickets sont confidentiels par défaut, de sorte que seuls les membres du projet ayant le rôle Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire peuvent les consulter.

Dans les projets privés et internes, vous pouvez configurer GitLab de sorte que les nouveaux tickets ne soient pas confidentiels par défaut et que tout membre du projet puisse les consulter.

Dans les projets publics, ce paramètre n'est pas disponible car les nouveaux tickets sont toujours confidentiels par défaut.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour désactiver ce paramètre :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Service d'assistance**.
1. Décochez la case **Les nouveaux tickets sont confidentiels par défaut**.
1. Sélectionnez **Enregistrer les modifications**.

## Rouvrir les tickets lorsqu'un participant externe commente {#reopen-tickets-when-an-external-participant-comments}

Vous pouvez configurer GitLab pour rouvrir les tickets fermés lorsqu'un participant externe ajoute un nouveau commentaire sur un ticket par e-mail. Cela ajoute également un commentaire interne mentionnant les personnes assignées au ticket et crée des éléments de la liste de tâches pour elles.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une présentation guidée, voir [une courte vidéo de démonstration](https://youtu.be/163wDM1e43o).
<!-- Video published on 2023-12-12 -->

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour activer ce paramètre :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Service d'assistance**.
1. Cochez la case **Rouvrir les tickets sur une nouvelle note d'un participant externe**.
1. Sélectionnez **Enregistrer les modifications**.

## Adresse e-mail personnalisée {#custom-email-address}

{{< details >}}

- Statut : version bêta

{{< /details >}}

Configurez une adresse e-mail personnalisée à afficher comme expéditeur de vos communications d'assistance. Maintenez l'identité de votre marque et inspirez confiance aux demandeurs d'assistance grâce à un domaine qu'ils reconnaissent.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une vue d'ensemble, voir [une courte vidéo de démonstration](https://youtu.be/_moD5U3xcQs).
<!-- Video published on 2023-09-12 -->

Cette fonctionnalité est en [version bêta](../../../policy/development_stages_support.md#beta). Une fonctionnalité en version bêta n'est pas prête pour la production, mais il est peu probable qu'elle soit modifiée de manière significative avant sa release. Essayez les fonctionnalités en version bêta et partagez vos retours dans le [ticket de feedback](https://gitlab.com/gitlab-org/gitlab/-/issues/416637).

### Prérequis {#prerequisites}

Vous pouvez utiliser une seule adresse e-mail personnalisée pour le Service d'assistance par projet, et elle doit être unique dans l'ensemble de l'instance.

L'adresse e-mail personnalisée que vous souhaitez utiliser doit répondre à toutes les exigences suivantes :

- Vous pouvez configurer la redirection d'e-mails.
- Les e-mails redirigés préservent l'en-tête `From` d'origine.
- Votre fournisseur de services doit prendre en charge le sous-adressage. Une adresse e-mail se compose d'une partie locale (tout ce qui précède `@`) et d'une partie domaine.

  Avec le sous-adressage d'e-mail, vous pouvez créer des variantes uniques d'une adresse e-mail en ajoutant le symbole `+` suivi de n'importe quel texte à la partie locale. Pour l'adresse e-mail `support@example.com`, vérifiez si le sous-adressage est pris en charge en envoyant un e-mail à `support+1@example.com`. Cet e-mail devrait apparaître dans votre boîte de réception.
- Vous disposez d'identifiants SMTP (idéalement, vous devriez utiliser un mot de passe d'application). Le nom d'utilisateur et le mot de passe sont stockés dans la base de données à l'aide du standard AES (Advanced Encryption Standard) avec une clé de 256 bits.
- L'**Hôte SMTP** doit être résolvable depuis le réseau de votre instance GitLab (sur GitLab Self-Managed) ou depuis l'internet public (sur GitLab.com).
- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.
- Le Service d'assistance doit être configuré pour le projet.

### Configurer une adresse e-mail personnalisée {#configure-a-custom-email-address}

Configurez et vérifiez une adresse e-mail personnalisée lorsque vous souhaitez envoyer des e-mails du Service d'assistance avec votre propre adresse e-mail.

> [!warning]
> Lorsque vous configurez la redirection d'e-mails, utilisez l'adresse indiquée dans **Adresse de courriel du service d'assistance vers laquelle rediriger les courriels** dans le formulaire d'e-mail personnalisé (l'adresse `incoming+...`). Ne redirigez pas vers l'adresse alias (`contact-project+...`) en haut de la page des paramètres du Service d'assistance. La redirection vers l'adresse alias provoque des échecs de vérification `Incorrect forwarding target`.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Service d'assistance** et trouvez la section **Configurer une adresse de courriel personnalisée**.
1. Copiez l'adresse e-mail depuis **Adresse de courriel du service d'assistance vers laquelle rediriger les courriels**. Il s'agit de l'adresse `incoming+...` que vous devez utiliser comme cible de redirection.
1. Dans votre fournisseur de messagerie (par exemple Gmail ou Microsoft 365), configurez la redirection d'e-mails depuis votre adresse e-mail personnalisée vers l'adresse copiée à l'étape précédente.
1. De retour dans GitLab, renseignez les champs restants.
1. Sélectionnez **Enregistrer et tester la connexion**.

La configuration a été enregistrée et la vérification de l'adresse e-mail personnalisée est déclenchée.

#### Vérification {#verification}

1. Après avoir finalisé la configuration, tous les propriétaires du projet et l'administrateur qui a enregistré la configuration d'e-mail personnalisé reçoivent un e-mail de notification.
1. Un e-mail de vérification est envoyé à l'aide des identifiants SMTP fournis à l'adresse e-mail personnalisée (avec une partie sous-adresse). L'e-mail contient un jeton de vérification. Lorsque la redirection d'e-mails est correctement configurée et que tous les prérequis sont satisfaits, l'e-mail est redirigé vers votre adresse du Service d'assistance et ingéré par GitLab. GitLab vérifie les conditions suivantes :
   1. GitLab peut envoyer un e-mail à l'aide des identifiants SMTP.
   1. Le sous-adressage est pris en charge (avec la partie sous-adresse `+verify`).
   1. L'en-tête `From` est préservé après la redirection.
   1. Le jeton de vérification est correct.
   1. L'e-mail est reçu dans les 30 minutes.

En général, le processus ne prend que quelques minutes.

Pour annuler la vérification à tout moment ou en cas d'échec, sélectionnez **Réinitialiser l'adresse de courriel personnalisée**. La page des paramètres se met à jour en conséquence et reflète l'état actuel de la vérification. Les identifiants SMTP sont supprimés et vous pouvez recommencer la configuration.

En cas d'échec ou de succès, tous les propriétaires du projet et l'utilisateur qui a déclenché le processus de vérification reçoivent un e-mail de notification avec le résultat de la vérification. Si la vérification a échoué, l'e-mail contient également des détails sur la raison de l'échec.

Si la vérification a réussi, l'adresse e-mail personnalisée est prête à être utilisée. Vous pouvez maintenant activer l'envoi des e-mails du Service d'assistance avec l'adresse e-mail personnalisée.

#### Résoudre les problèmes de configuration {#troubleshooting-your-configuration}

Lors de la configuration d'un e-mail personnalisé, vous pourriez rencontrer les problèmes suivants.

##### Identifiants non valides {#invalid-credentials}

Vous pourriez obtenir une erreur indiquant :

```plaintext
The given credentials (username and password) were rejected by the SMTP server,
or you need to explicitly set an authentication method.
```

Ce problème se produit lorsque le serveur SMTP rejette les identifiants d'authentification.

Pour résoudre ce problème :

1. Vérifiez que votre nom d'utilisateur et votre mot de passe sont corrects.
1. Si GitLab ne peut pas sélectionner automatiquement une méthode d'authentification prise en charge, effectuez l'une des opérations suivantes :
   - Testez les méthodes d'authentification disponibles : **Plain**, **Connexion** et **CRAM-MD5**.
   - Vérifiez les méthodes d'authentification prises en charge par votre serveur SMTP en exécutant cette commande sur le serveur GitLab :

     ```shell
          swaks --to user@example.com \
                --from support@example.com \
                --auth-user support@example.com \
                --server smtp@example.com:587 \
                -tls-optional \
                --auth-password your-app-password
     ```

     Dans la sortie, trouvez la ligne commençant par `250-AUTH`, puis sélectionnez l'une des méthodes d'authentification prises en charge dans le formulaire de configuration de l'e-mail personnalisé.

1. Si vous utilisez Microsoft 365 et que l'erreur persiste, désactivez l'accès conditionnel et répétez les étapes précédentes.

##### Cible de redirection incorrecte {#incorrect-forwarding-target}

Vous pourriez obtenir une erreur indiquant qu'une cible de redirection incorrecte a été utilisée.

Cela se produit lorsque l'e-mail de vérification a été redirigé vers une adresse e-mail différente de l'adresse du Service d'assistance spécifique au projet affichée dans le formulaire de configuration de l'e-mail personnalisé.

Vous devez utiliser l'adresse du Service d'assistance générée à partir de `incoming_email`. La redirection vers l'adresse alias supplémentaire du Service d'assistance générée depuis `service_desk_email` n'est pas prise en charge, car elle ne prend pas en charge toutes les fonctionnalités de réponse par e-mail.

Pour résoudre ce problème :

1. Trouvez l'adresse e-mail correcte vers laquelle rediriger les e-mails. L'une ou l'autre des options :
   - Notez l'adresse dans l'e-mail de résultat de vérification que tous les propriétaires du projet et l'utilisateur qui a déclenché le processus de vérification reçoivent.
   - Copiez l'adresse depuis le champ **Adresse de courriel du service d'assistance vers laquelle rediriger les courriels** dans le formulaire de configuration de l'e-mail personnalisé.
1. Redirigez tous les e-mails envoyés à l'adresse e-mail personnalisée vers la bonne adresse e-mail cible.

### Activer ou désactiver l'adresse e-mail personnalisée {#enable-or-disable-the-custom-email-address}

Une fois l'adresse e-mail personnalisée vérifiée, les administrateurs peuvent activer ou désactiver l'envoi des e-mails du Service d'assistance avec l'adresse e-mail personnalisée.

Pour **activer** l'adresse e-mail personnalisée :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Service d'assistance**.
1. Activez le bouton **Activer l'adresse de courriel personnalisée**. Les e-mails du Service d'assistance destinés aux participants externes sont envoyés à l'aide des identifiants SMTP.

Pour **désactiver** l'adresse e-mail personnalisée :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Service d'assistance**.
1. Désactivez le bouton **Activer l'adresse de courriel personnalisée**. Étant donné que vous avez configuré la redirection d'e-mails, les e-mails envoyés à votre adresse e-mail personnalisée continuent d'être traités et apparaissent comme des tickets du Service d'assistance dans votre projet.

   Les e-mails du Service d'assistance destinés aux participants externes sont désormais envoyés à l'aide de la configuration d'e-mail sortant par défaut de l'instance GitLab.

### Modifier ou supprimer la configuration d'e-mail personnalisé {#change-or-remove-custom-email-configuration}

Pour modifier la configuration d'e-mail personnalisé, vous devez la réinitialiser, la supprimer, puis reconfigurer l'e-mail personnalisé.

Pour réinitialiser la configuration à n'importe quelle étape du processus, sélectionnez **Réinitialiser l'adresse de courriel personnalisée**. Les identifiants sont alors supprimés de la base de données.

### Adresse e-mail de réponse personnalisée {#custom-email-reply-address}

Les participants externes peuvent [répondre par e-mail](../../../administration/reply_by_email.md) aux tickets du Service d'assistance. GitLab utilise une adresse e-mail de réponse avec une clé de réponse de 32 caractères correspondant au ticket. Lorsqu'un e-mail personnalisé est configuré, GitLab génère l'adresse de réponse à partir de cet e-mail.

### Utiliser Google Workspace avec votre propre domaine {#use-google-workspace-with-your-own-domain}

Configurez une adresse e-mail personnalisée pour le Service d'assistance lorsque vous utilisez Google Workspace avec votre propre domaine.

Prérequis :

- Vous disposez déjà d'un compte Google Workspace.
- Vous pouvez créer de nouveaux comptes pour votre locataire.

Pour configurer une adresse e-mail personnalisée du Service d'assistance avec Google Workspace :

1. [Configurez un compte Google Workspace](#configure-a-google-workspace-account).
1. [Configurez la redirection d'e-mails dans Google Workspace](#configure-email-forwarding-in-google-workspace).
1. [Configurez une adresse e-mail personnalisée avec un compte Google Workspace](#configure-custom-email-address-using-a-google-workspace-account).

#### Configurer un compte Google Workspace {#configure-a-google-workspace-account}

Tout d'abord, vous devez créer et configurer un compte Google Workspace.

Dans Google Workspace :

1. Créez un nouveau compte pour l'adresse e-mail personnalisée que vous souhaitez utiliser (par exemple, `support@example.com`).
1. Connectez-vous à ce compte et activez l'authentification à deux facteurs : `https://myaccount.google.com/u/3/signinoptions/two-step-verification`
1. Créez un mot de passe d'application que vous pouvez utiliser comme mot de passe SMTP : `https://myaccount.google.com/u/3/apppasswords` Conservez-le dans un endroit sécurisé et supprimez les espaces entre les caractères.

Ensuite, vous devez [configurer la redirection d'e-mails dans Google Workspace](#configure-email-forwarding-in-google-workspace).

#### Configurer la redirection d'e-mails dans Google Workspace {#configure-email-forwarding-in-google-workspace}

Les étapes suivantes nécessitent de passer entre GitLab et Google Workspace.

Dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**
1. Développez **Service d'assistance**.
1. Notez l'adresse e-mail sous **Adresse de courriel du service d'assistance vers laquelle rediriger les courriels**.

Dans Google Workspace :

1. Connectez-vous au compte e-mail personnalisé et ouvrez les paramètres [**Transfert et POP/IMAP**](https://mail.google.com/mail/u/0/#settings/fwdandpop).
1. Sélectionnez **Ajouter une adresse de transfert**.
1. Saisissez l'adresse du Service d'assistance depuis le formulaire d'e-mail personnalisé.
1. Sélectionnez **Suivant**.
1. Confirmez votre saisie et sélectionnez **Poursuivre**. Google envoie un e-mail à l'adresse du Service d'assistance et demande un code de confirmation.

Dans GitLab :

1. Sélectionnez **Forfait** > **Éléments de travail**, puis filtrez par **Type** = **Ticket**. Attendez qu'un nouveau ticket soit créé à partir de l'e-mail de confirmation de Google.
1. Sélectionnez le ticket et notez le code de confirmation.
1. Facultatif. Supprimez le ticket.

Dans Google Workspace :

1. Saisissez le code de confirmation et sélectionnez **Vérifier**.
1. Sélectionnez **Transférer une copie des e-mails entrants vers** et assurez-vous que l'adresse du Service d'assistance est sélectionnée dans la liste déroulante.
1. En bas de la page, sélectionnez **Enregistrer les modifications**.

Ensuite, [configurez une adresse e-mail personnalisée avec un compte Google Workspace](#configure-custom-email-address-using-a-google-workspace-account) pour l'utiliser avec le Service d'assistance.

#### Configurer une adresse e-mail personnalisée avec un compte Google Workspace {#configure-custom-email-address-using-a-google-workspace-account}

Dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Service d'assistance** et trouvez les paramètres d'e-mail personnalisé.
1. Remplissez les champs :
   - **Adresse de courriel personnalisée** : votre adresse e-mail personnalisée.
   - **Hôte SMTP** : `smtp.gmail.com`.
   - **Port SMTP** : `587`.
   - **Nom d'utilisateur SMTP** : prérempli avec l'adresse e-mail personnalisée.
   - **Mot de passe SMTP** : le mot de passe d'application que vous avez précédemment créé pour le compte e-mail personnalisé.
   - **Méthode d'authentification SMTP** : laissez GitLab sélectionner une méthode prise en charge par le serveur (recommandé).
1. Sélectionnez **Enregistrer et tester la connexion**.
1. Après le [processus de vérification](#verification), vous pouvez [activer l'adresse e-mail personnalisée](#enable-or-disable-the-custom-email-address).

### Utiliser Microsoft 365 (Exchange Online) avec votre propre domaine {#use-microsoft-365-exchange-online-with-your-own-domain}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/496396) dans GitLab 17.5.

{{< /history >}}

Configurez une adresse e-mail personnalisée pour le Service d'assistance lorsque vous utilisez Microsoft 365 (Exchange) avec votre propre domaine.

Prérequis :

- Vous disposez déjà d'un compte Microsoft 365.
- Vous pouvez créer de nouveaux comptes pour votre locataire.

Pour configurer une adresse e-mail personnalisée du Service d'assistance avec Microsoft 365 :

1. [Configurez un compte Microsoft 365](#configure-a-microsoft-365-account).
1. [Configurez la redirection d'e-mails dans Microsoft 365](#configure-email-forwarding-in-microsoft-365).
1. [Configurez une adresse e-mail personnalisée avec un compte Microsoft 365](#configure-custom-email-address-using-a-microsoft-365-account).

#### Configurer un compte Microsoft 365 {#configure-a-microsoft-365-account}

Tout d'abord, vous devez créer et configurer un compte Microsoft 365. Dans ce guide, utilisez un utilisateur sous licence pour la boîte de réception de l'e-mail personnalisé. Vous pouvez également tester d'autres options de configuration.

Dans le [Centre d'administration Microsoft 365](https://admin.microsoft.com/Adminportal/Home#/homepage) :

1. Créez un nouveau compte pour l'adresse e-mail personnalisée que vous souhaitez utiliser (par exemple, `support@example.com`).
   1. Développez **Utilisateurs** et sélectionnez **Utilisateurs actifs** dans le menu.
   1. Sélectionnez **Ajouter un utilisateur** et suivez les instructions à l'écran.
1. Dans Microsoft Entra (anciennement appelé Active Directory), activez l'authentification à deux facteurs pour le compte.
1. [Autorisez les utilisateurs à créer des mots de passe d'application](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-app-passwords).
1. Activez **SMTP authentifié** pour le compte.
   1. Sélectionnez le compte dans la liste.
   1. Dans le volet, sélectionnez **Messagerie**.
   1. Sous **Applications de messagerie**, sélectionnez **Gérer les applications de messagerie**.
   1. Cochez **SMTP authentifié** et sélectionnez **Enregistrer les modifications**.
1. En fonction de votre configuration globale d'Exchange Online, vous pourriez avoir besoin de configurer les éléments suivants :
   1. Utilisez Azure Cloud Shell pour autoriser l'authentification du client SMTP :

      ```powershell
      Set-TransportConfig -SmtpClientAuthenticationDisabled $false
      ```

   1. Utilisez Azure Cloud Shell pour autoriser les [clients TLS hérités utilisant SMTP AUTH](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/opt-in-exchange-online-endpoint-for-legacy-tls-using-smtp-auth) :

      ```powershell
      Set-TransportConfig -AllowLegacyTLSClients $true
      ```

   1. Si vous souhaitez transférer des e-mails vers un destinataire externe, consultez ce guide sur la façon d'activer le [transfert d'e-mails externe](https://learn.microsoft.com/en-gb/defender-office-365/outbound-spam-policies-external-email-forwarding). Vous pourriez également vouloir [créer une stratégie anti-spam sortante](https://security.microsoft.com/antispam) pour autoriser le transfert vers des destinataires externes uniquement pour les utilisateurs qui en ont besoin.
1. Connectez-vous à ce compte et activez l'authentification à deux facteurs.
   <!-- vale gitlab_base.SubstitutionWarning = NO -->
   1. Dans le menu en haut à droite, sélectionnez **Afficher le compte** et [accédez à **Informations de sécurité**](https://mysignins.microsoft.com/security-info).
   <!-- vale gitlab_base.SubstitutionWarning = YES -->
   1. Sélectionnez **Ajouter une méthode de connexion** et sélectionnez une méthode qui vous convient (application d'authentification, téléphone ou e-mail).
   1. Suivez les instructions à l'écran.
<!-- vale gitlab_base.SubstitutionWarning = NO -->
1. Sur la page [**Informations de sécurité**](https://mysignins.microsoft.com/security-info), créez un mot de passe d'application que vous pouvez utiliser comme mot de passe SMTP.
<!-- vale gitlab_base.SubstitutionWarning = YES -->
   1. Sélectionnez **Ajouter une méthode de connexion** et sélectionnez **Mot de passe d'application** dans la liste déroulante.
   1. Donnez un nom descriptif au mot de passe d'application, par exemple `GitLab SD`.
   1. Sélectionnez **Suivant**.
   1. Copiez le mot de passe affiché et conservez-le dans un endroit sécurisé.
   1. Facultatif. Assurez-vous de pouvoir envoyer des e-mails via SMTP à l'aide de l'[outil en ligne de commande `swaks`](https://www.jetmore.org/john/code/swaks/).
   1. Exécutez la commande suivante avec vos identifiants et utilisez le mot de passe d'application comme `auth-password` :

      ```shell
      swaks --to your-email@example.com \
            --from custom-email@example.com \
            --auth-user custom-email@example.com \
            --server smtp.office365.com:587 \
            -tls-optional \
            --auth-password <your_app_password>
      ```

Ensuite, vous devez [configurer la redirection d'e-mails dans Microsoft 365](#configure-email-forwarding-in-microsoft-365).

#### Configurer la redirection d'e-mails dans Microsoft 365 {#configure-email-forwarding-in-microsoft-365}

Les étapes suivantes nécessitent de passer entre GitLab et le Centre d'administration Microsoft 365.

Dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**
1. Développez **Service d'assistance**.
1. Notez l'adresse e-mail sous **Adresse de courriel du service d'assistance vers laquelle rediriger les courriels** sans la partie sous-adresse.

   Les e-mails ne sont pas transférés si l'adresse du destinataire contient une sous-adresse (par exemple, les adresses de réponse générées par GitLab) et que l'adresse e-mail de transfert contient une sous-adresse (le champ **Adresse de courriel du service d'assistance vers laquelle rediriger les courriels**).

   Par exemple, `incoming+group-project-12346426-issue-@incoming.gitlab.com` devient `incoming@incoming.gitlab.com`. C'est acceptable car Exchange Online préserve l'adresse e-mail personnalisée dans l'en-tête `To` après le transfert, et GitLab peut attribuer le projet correct en fonction de l'adresse e-mail personnalisée.

Dans le [Centre d'administration Microsoft 365](https://admin.microsoft.com/Adminportal/Home#/homepage) :

<!-- vale gitlab_base.SubstitutionWarning = NO -->
1. Développez **Utilisateurs** et sélectionnez **Utilisateurs actifs** dans le menu.
<!-- vale gitlab_base.SubstitutionWarning = YES -->
1. Sélectionnez dans la liste le compte que vous souhaitez utiliser pour l'e-mail personnalisé.
1. Dans le volet, sélectionnez **Messagerie**.
1. Sous **Transfert d'e-mail**, sélectionnez **Gérer le transfert d'e-mail**.
1. Cochez **Transférer tous les e-mails envoyés à cette boîte de réception**.
1. Saisissez l'adresse du Service d'assistance depuis le formulaire d'e-mail personnalisé dans **Adresse e-mail de transfert** sans la partie sous-adresse.
1. Sélectionnez **Enregistrer les modifications**.

Ensuite, [configurez une adresse e-mail personnalisée avec un compte Microsoft 365](#configure-custom-email-address-using-a-microsoft-365-account) pour l'utiliser avec le Service d'assistance.

#### Configurer une adresse e-mail personnalisée avec un compte Microsoft 365 {#configure-custom-email-address-using-a-microsoft-365-account}

Dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**
1. Développez **Service d'assistance** et trouvez les paramètres d'e-mail personnalisé.
1. Remplissez les champs :
   - **Adresse de courriel personnalisée** : votre adresse e-mail personnalisée.
   - **Hôte SMTP** : `smtp.office365.com`.
   - **Port SMTP** : `587`.
   - **Nom d'utilisateur SMTP** : prérempli avec l'adresse e-mail personnalisée.
   - **Mot de passe SMTP** : le mot de passe d'application que vous avez précédemment créé pour le compte e-mail personnalisé.
   - **Méthode d'authentification SMTP** : connexion.
1. Sélectionnez **Enregistrer et tester la connexion**.
1. Après le [processus de vérification](#verification), vous pouvez [activer l'adresse e-mail personnalisée](#enable-or-disable-the-custom-email-address).

### Problèmes connus {#known-issues}

- Certains fournisseurs de services n'autorisent plus les connexions SMTP. Vous pouvez souvent les activer pour chaque utilisateur et créer un mot de passe d'application.

## Utiliser un alias d'e-mail supplémentaire pour le Service d'assistance {#use-an-additional-service-desk-alias-email}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Vous pouvez utiliser une adresse e-mail alias supplémentaire pour le Service d'assistance d'une instance.

Pour ce faire, vous devez configurer un [`service_desk_email`](#configure-service-desk-alias-email) dans la configuration de l'instance. Vous pouvez également configurer un [suffixe personnalisé](#configure-a-suffix-for-service-desk-alias-email) qui remplace la partie `-issue-` par défaut dans la partie sous-adresse.

### Configurer l'e-mail alias du Service d'assistance {#configure-service-desk-alias-email}

> [!note]
> Sur GitLab.com, une boîte de réception personnalisée est déjà configurée avec `contact-project+%{key}@incoming.gitlab.com` comme adresse e-mail. Vous pouvez toujours configurer le [suffixe personnalisé](#configure-a-suffix-for-service-desk-alias-email) dans les paramètres du projet.

Le Service d'assistance utilise par défaut la configuration des [e-mails entrants](../../../administration/incoming_email.md). Cependant, pour disposer d'une adresse e-mail distincte pour le Service d'assistance, configurez `service_desk_email` avec un [suffixe personnalisé](#configure-a-suffix-for-service-desk-alias-email) dans les paramètres du projet.

Prérequis :

- Le paramètre `address` doit inclure l'espace réservé `+%{key}` dans la partie `user` de l'adresse, avant le `@`. L'espace réservé est utilisé pour identifier le projet dans lequel le ticket doit être créé.
- Les configurations `service_desk_email` et `incoming_email` doivent toujours utiliser des boîtes de réception distinctes pour s'assurer que les e-mails du Service d'assistance sont traités correctement.

Pour configurer une boîte de réception personnalisée pour le Service d'assistance avec IMAP, ajoutez intégralement les extraits suivants à votre fichier de configuration :

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

```ruby
gitlab_rails['service_desk_email_enabled'] = true
gitlab_rails['service_desk_email_address'] = "project_contact+%{key}@gmail.com"
gitlab_rails['service_desk_email_email'] = "project_contact@gmail.com"
gitlab_rails['service_desk_email_password'] = "[REDACTED]"
gitlab_rails['service_desk_email_mailbox_name'] = "inbox"
gitlab_rails['service_desk_email_idle_timeout'] = 60
gitlab_rails['service_desk_email_log_file'] = "/var/log/gitlab/mailroom/mail_room_json.log"
gitlab_rails['service_desk_email_host'] = "imap.gmail.com"
gitlab_rails['service_desk_email_port'] = 993
gitlab_rails['service_desk_email_ssl'] = true
gitlab_rails['service_desk_email_start_tls'] = false
```

{{< /tab >}}

{{< tab title="Auto-compilée (source)" >}}

```yaml
service_desk_email:
  enabled: true
  address: "project_contact+%{key}@example.com"
  user: "project_contact@example.com"
  password: "[REDACTED]"
  host: "imap.gmail.com"
  delivery_method: webhook
  secret_file: .gitlab-mailroom-secret
  port: 993
  ssl: true
  start_tls: false
  log_path: "log/mailroom.log"
  mailbox: "inbox"
  idle_timeout: 60
  expunge_deleted: true
```

{{< /tab >}}

{{< /tabs >}}

Les options de configuration sont identiques à celles utilisées pour configurer les [e-mails entrants](../../../administration/incoming_email.md#set-it-up).

#### Utiliser des identifiants chiffrés {#use-encrypted-credentials}

Au lieu de stocker les identifiants d'e-mail du Service d'assistance en texte brut dans les fichiers de configuration, vous pouvez éventuellement utiliser un fichier chiffré pour les identifiants d'e-mail entrant.

Prérequis :

- Pour utiliser des identifiants chiffrés, vous devez d'abord activer la [configuration chiffrée](../../../administration/encrypted_configuration.md).

Les éléments de configuration pris en charge pour le fichier chiffré sont :

- `user`
- `password`

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

1. Si votre configuration du Service d'assistance dans `/etc/gitlab/gitlab.rb` ressemblait initialement à ceci :

   ```ruby
   gitlab_rails['service_desk_email_email'] = "service-desk-email@mail.example.com"
   gitlab_rails['service_desk_email_password'] = "examplepassword"
   ```

1. Modifiez le secret chiffré :

   ```shell
   sudo gitlab-rake gitlab:service_desk_email:secret:edit EDITOR=vim
   ```

1. Saisissez le contenu non chiffré du secret d'e-mail du Service d'assistance :

   ```yaml
   user: 'service-desk-email@mail.example.com'
   password: 'examplepassword'
   ```

1. Modifiez `/etc/gitlab/gitlab.rb` et supprimez les paramètres `service_desk` pour `email` et `password`.
1. Enregistrez le fichier et reconfigurez GitLab :

   ```shell
   sudo gitlab-ctl reconfigure
   ```

{{< /tab >}}

{{< tab title="Chart Helm (Kubernetes)" >}}

Utilisez un secret Kubernetes pour stocker le mot de passe d'e-mail du Service d'assistance. Pour plus d'informations, consultez les [secrets IMAP Helm](https://docs.gitlab.com/charts/installation/secrets/#imap-password-for-service-desk-emails).

{{< /tab >}}

{{< tab title="Docker" >}}

1. Si votre configuration du Service d'assistance dans `docker-compose.yml` ressemblait initialement à ceci :

   ```yaml
   version: "3.6"
   services:
     gitlab:
       image: 'gitlab/gitlab-ee:latest'
       restart: always
       hostname: 'gitlab.example.com'
       environment:
         GITLAB_OMNIBUS_CONFIG: |
           gitlab_rails['service_desk_email_email'] = "service-desk-email@mail.example.com"
           gitlab_rails['service_desk_email_password'] = "examplepassword"
   ```

1. Entrez dans le conteneur et modifiez le secret chiffré :

   ```shell
   sudo docker exec -t <container_name> bash
   gitlab-rake gitlab:service_desk_email:secret:edit EDITOR=editor
   ```

1. Saisissez le contenu non chiffré du secret du Service d'assistance :

   ```yaml
   user: 'service-desk-email@mail.example.com'
   password: 'examplepassword'
   ```

1. Modifiez `docker-compose.yml` et supprimez les paramètres `service_desk` pour `email` et `password`.
1. Enregistrez le fichier et redémarrez GitLab :

   ```shell
   docker compose up -d
   ```

{{< /tab >}}

{{< tab title="Auto-compilée (source)" >}}

1. Si votre configuration du Service d'assistance dans `/home/git/gitlab/config/gitlab.yml` ressemblait initialement à ceci :

   ```yaml
   production:
     service_desk_email:
       user: 'service-desk-email@mail.example.com'
       password: 'examplepassword'
   ```

1. Modifiez le secret chiffré :

   ```shell
   bundle exec rake gitlab:service_desk_email:secret:edit EDITOR=vim RAILS_ENVIRONMENT=production
   ```

1. Saisissez le contenu non chiffré du secret du Service d'assistance :

   ```yaml
   user: 'service-desk-email@mail.example.com'
   password: 'examplepassword'
   ```

1. Modifiez `/home/git/gitlab/config/gitlab.yml` et supprimez les paramètres `service_desk_email:` pour `user` et `password`.
1. Enregistrez le fichier et redémarrez GitLab et Mailroom

   ```shell
   # For systems running systemd
   sudo systemctl restart gitlab.target

   # For systems running SysV init
   sudo service gitlab restart
   ```

{{< /tab >}}

{{< /tabs >}}

#### Microsoft Graph {#microsoft-graph}

`service_desk_email` peut être configuré pour lire les boîtes de réception Microsoft Exchange Online avec l'API Microsoft Graph au lieu d'IMAP. Configurez une application OAuth 2.0 pour Microsoft Graph [de la même manière que pour les e-mails entrants](../../../administration/incoming_email.md#microsoft-graph).

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

1. Modifiez `/etc/gitlab/gitlab.rb` et ajoutez les lignes suivantes en substituant les valeurs souhaitées :

   ```ruby
   gitlab_rails['service_desk_email_enabled'] = true
   gitlab_rails['service_desk_email_address'] = "project_contact+%{key}@example.onmicrosoft.com"
   gitlab_rails['service_desk_email_email'] = "project_contact@example.onmicrosoft.com"
   gitlab_rails['service_desk_email_mailbox_name'] = "inbox"
   gitlab_rails['service_desk_email_log_file'] = "/var/log/gitlab/mailroom/mail_room_json.log"
   gitlab_rails['service_desk_email_inbox_method'] = 'microsoft_graph'
   gitlab_rails['service_desk_email_inbox_options'] = {
      'tenant_id': '<YOUR-TENANT-ID>',
      'client_id': '<YOUR-CLIENT-ID>',
      'client_secret': '<YOUR-CLIENT-SECRET>',
      'poll_interval': 60  # Optional
   }
   ```

   Pour Microsoft Cloud for US Government ou [d'autres déploiements Azure](https://learn.microsoft.com/en-us/graph/deployments), configurez les paramètres `azure_ad_endpoint` et `graph_endpoint`. Par exemple :

   ```ruby
   gitlab_rails['service_desk_email_inbox_options'] = {
      'azure_ad_endpoint': 'https://login.microsoftonline.us',
      'graph_endpoint': 'https://graph.microsoft.us',
      'tenant_id': '<YOUR-TENANT-ID>',
      'client_id': '<YOUR-CLIENT-ID>',
      'client_secret': '<YOUR-CLIENT-SECRET>',
      'poll_interval': 60  # Optional
   }
   ```

{{< /tab >}}

{{< tab title="Chart Helm (Kubernetes)" >}}

1. Créez le [secret Kubernetes contenant le secret client de l'application OAuth 2.0](https://docs.gitlab.com/charts/installation/secrets/#microsoft-graph-client-secret-for-service-desk-emails) :

   ```shell
   kubectl create secret generic service-desk-email-client-secret --from-literal=secret=<YOUR-CLIENT_SECRET>
   ```

1. Créez le [secret Kubernetes pour le jeton d'authentification d'e-mail du Service d'assistance GitLab](https://docs.gitlab.com/charts/installation/secrets/#gitlab-service-desk-email-auth-token). Remplacez `<name>` par le nom du [nom de release Helm](https://helm.sh/docs/intro/using_helm/) pour l'installation de GitLab :

   ```shell
   kubectl create secret generic <name>-service-desk-email-auth-token --from-literal=authToken=$(head -c 512 /dev/urandom | LC_CTYPE=C tr -cd 'a-zA-Z0-9' | head -c 32 | base64)
   ```

1. Exportez les valeurs Helm :

   ```shell
   helm get values gitlab > gitlab_values.yaml
   ```

1. Modifiez `gitlab_values.yaml` :

   ```yaml
   global:
     appConfig:
     serviceDeskEmail:
       enabled: true
       address: "project_contact+%{key}@example.onmicrosoft.com"
       user: "project_contact@example.onmicrosoft.com"
       mailbox: inbox
       inboxMethod: microsoft_graph
       azureAdEndpoint: https://login.microsoftonline.com
       graphEndpoint: https://graph.microsoft.com
       tenantId: "YOUR-TENANT-ID"
       clientId: "YOUR-CLIENT-ID"
       clientSecret:
         secret: service-desk-email-client-secret
         key: secret
       deliveryMethod: webhook
       authToken:
         secret: <name>-service-desk-email-auth-token
         key: authToken
   ```

   Pour Microsoft Cloud for US Government ou [d'autres déploiements Azure](https://learn.microsoft.com/en-us/graph/deployments), configurez les paramètres `azureAdEndpoint` et `graphEndpoint`. Ces champs sont sensibles à la casse :

   ```yaml
   global:
     appConfig:
     serviceDeskEmail:
       [..]
       azureAdEndpoint: https://login.microsoftonline.us
       graphEndpoint: https://graph.microsoft.us
       [..]
   ```

1. Enregistrez le fichier et appliquez les nouvelles valeurs :

   ```shell
   helm upgrade -f gitlab_values.yaml gitlab gitlab/gitlab
   ```

{{< /tab >}}

{{< tab title="Docker" >}}

1. Modifiez `docker-compose.yml` :

   ```yaml
   version: "3.6"
   services:
     gitlab:
       environment:
         GITLAB_OMNIBUS_CONFIG: |
           gitlab_rails['service_desk_email_enabled'] = true
           gitlab_rails['service_desk_email_address'] = "project_contact+%{key}@example.onmicrosoft.com"
           gitlab_rails['service_desk_email_email'] = "project_contact@example.onmicrosoft.com"
           gitlab_rails['service_desk_email_mailbox_name'] = "inbox"
           gitlab_rails['service_desk_email_log_file'] = "/var/log/gitlab/mailroom/mail_room_json.log"
           gitlab_rails['service_desk_email_inbox_method'] = 'microsoft_graph'
           gitlab_rails['service_desk_email_inbox_options'] = {
             'tenant_id': '<YOUR-TENANT-ID>',
             'client_id': '<YOUR-CLIENT-ID>',
             'client_secret': '<YOUR-CLIENT-SECRET>',
             'poll_interval': 60  # Optional
           }
   ```

1. Enregistrez le fichier et redémarrez GitLab :

   ```shell
   docker compose up -d
   ```

Pour Microsoft Cloud for US Government ou [d'autres déploiements Azure](https://learn.microsoft.com/en-us/graph/deployments), configurez les paramètres `azure_ad_endpoint` et `graph_endpoint` :

1. Modifiez `docker-compose.yml` :

   ```yaml
   version: "3.6"
   services:
     gitlab:
       environment:
         GITLAB_OMNIBUS_CONFIG: |
           gitlab_rails['service_desk_email_enabled'] = true
           gitlab_rails['service_desk_email_address'] = "project_contact+%{key}@example.onmicrosoft.com"
           gitlab_rails['service_desk_email_email'] = "project_contact@example.onmicrosoft.com"
           gitlab_rails['service_desk_email_mailbox_name'] = "inbox"
           gitlab_rails['service_desk_email_log_file'] = "/var/log/gitlab/mailroom/mail_room_json.log"
           gitlab_rails['service_desk_email_inbox_method'] = 'microsoft_graph'
           gitlab_rails['service_desk_email_inbox_options'] = {
             'azure_ad_endpoint': 'https://login.microsoftonline.us',
             'graph_endpoint': 'https://graph.microsoft.us',
             'tenant_id': '<YOUR-TENANT-ID>',
             'client_id': '<YOUR-CLIENT-ID>',
             'client_secret': '<YOUR-CLIENT-SECRET>',
             'poll_interval': 60  # Optional
           }
   ```

1. Enregistrez le fichier et redémarrez GitLab :

   ```shell
   docker compose up -d
   ```

{{< /tab >}}

{{< tab title="Auto-compilée (source)" >}}

1. Modifiez `/home/git/gitlab/config/gitlab.yml` :

   ```yaml
     service_desk_email:
       enabled: true
       address: "project_contact+%{key}@example.onmicrosoft.com"
       user: "project_contact@example.onmicrosoft.com"
       mailbox: "inbox"
       delivery_method: webhook
       log_path: "log/mailroom.log"
       secret_file: .gitlab-mailroom-secret
       inbox_method: "microsoft_graph"
       inbox_options:
         tenant_id: "<YOUR-TENANT-ID>"
         client_id: "<YOUR-CLIENT-ID>"
         client_secret: "<YOUR-CLIENT-SECRET>"
         poll_interval: 60  # Optional
   ```

   Pour Microsoft Cloud for US Government ou [d'autres déploiements Azure](https://learn.microsoft.com/en-us/graph/deployments), configurez les paramètres `azure_ad_endpoint` et `graph_endpoint`. Par exemple :

   ```yaml
     service_desk_email:
       enabled: true
       address: "project_contact+%{key}@example.onmicrosoft.com"
       user: "project_contact@example.onmicrosoft.com"
       mailbox: "inbox"
       delivery_method: webhook
       log_path: "log/mailroom.log"
       secret_file: .gitlab-mailroom-secret
       inbox_method: "microsoft_graph"
       inbox_options:
         azure_ad_endpoint: "https://login.microsoftonline.us"
         graph_endpoint: "https://graph.microsoft.us"
         tenant_id: "<YOUR-TENANT-ID>"
         client_id: "<YOUR-CLIENT-ID>"
         client_secret: "<YOUR-CLIENT-SECRET>"
         poll_interval: 60  # Optional
   ```

{{< /tab >}}

{{< /tabs >}}

### Configurer un suffixe pour l'e-mail alias du Service d'assistance {#configure-a-suffix-for-service-desk-alias-email}

Vous pouvez définir un suffixe personnalisé dans les paramètres du Service d'assistance de votre projet.

Un suffixe ne peut contenir que des lettres minuscules (`a-z`), des chiffres (`0-9`) ou des traits de soulignement (`_`).

Une fois configuré, le suffixe personnalisé crée une nouvelle adresse e-mail du Service d'assistance, composée du paramètre `service_desk_email_address` et d'une clé au format : `<project_full_path>-<custom_suffix>`

Prérequis :

- Vous devez avoir configuré un [e-mail alias du Service d'assistance](#configure-service-desk-alias-email).

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Service d'assistance**.
1. Sous **Suffixe de l'adresse de courriel**, saisissez le suffixe à utiliser.
1. Sélectionnez **Enregistrer les modifications**.

Par exemple, supposons que les paramètres du Service d'assistance du projet `mygroup/myproject` présentent la configuration suivante :

- Le suffixe d'adresse e-mail est défini sur `support`.
- L'adresse e-mail du Service d'assistance est configurée sur `contact+%{key}@example.com`.

L'adresse e-mail du Service d'assistance pour ce projet est : `contact+mygroup-myproject-support@example.com`. L'adresse des [e-mails entrants](../../../administration/incoming_email.md) fonctionne toujours.

Si vous ne configurez pas de suffixe personnalisé, l'identification par défaut du projet est utilisée pour identifier le projet.

## Configurer l'ingestion d'e-mails dans des environnements multi-nœuds {#configure-email-ingestion-in-multi-node-environments}

Un environnement multi-nœuds est une configuration dans laquelle GitLab s'exécute sur plusieurs serveurs pour des raisons de scalabilité, de tolérance aux pannes et de performances.

GitLab utilise un processus distinct appelé `mail_room` pour ingérer les nouveaux e-mails non lus depuis les boîtes de réception `incoming_email` et `service_desk_email`.

### Chart Helm (Kubernetes) {#helm-chart-kubernetes}

Le [chart Helm GitLab](https://docs.gitlab.com/charts/) est composé de plusieurs sous-charts, dont le [sous-chart Mailroom](https://docs.gitlab.com/charts/charts/gitlab/mailroom/). Configurez les [paramètres communs pour `incoming_email`](https://docs.gitlab.com/charts/installation/command-line-options/#incoming-email-configuration) et les [paramètres communs pour `service_desk_email`](https://docs.gitlab.com/charts/installation/command-line-options/#service-desk-email-configuration).

### Package Linux (Omnibus) {#linux-package-omnibus}

Dans les environnements d'installation multi-nœuds du package Linux, exécutez `mail_room` sur un seul nœud. Exécutez-le soit sur un seul nœud `rails` (par exemple, `application_role`), soit complètement séparément.

#### Configurer tous les nœuds {#set-up-all-nodes}

1. Ajoutez une configuration de base pour `incoming_email` et `service_desk_email` sur chaque nœud afin d'afficher les adresses e-mail dans l'interface web et dans les e-mails générés.

   Trouvez la section `incoming_email` ou `service_desk_email` dans `/etc/gitlab/gitlab.rb` :

   {{< tabs >}}

   {{< tab title="`incoming_email`" >}}

   ```ruby
   gitlab_rails['incoming_email_enabled'] = true
   gitlab_rails['incoming_email_address'] = "incoming+%{key}@example.com"
   ```

   {{< /tab >}}

   {{< tab title="`service_desk_email`" >}}

   ```ruby
   gitlab_rails['service_desk_email_enabled'] = true
   gitlab_rails['service_desk_email_address'] = "project_contact+%{key}@example.com"
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. GitLab propose deux méthodes pour transporter les e-mails depuis `mail_room` vers l'application GitLab. Vous pouvez configurer la `delivery_method` pour chaque paramètre d'e-mail individuellement :
   1. Recommandé (par défaut) : `webhook` envoie le contenu de l'e-mail avec une requête API POST à votre application GitLab. Il utilise un jeton partagé pour s'authentifier. Si vous choisissez cette méthode, assurez-vous que le processus `mail_room` peut accéder au point de terminaison de l'API et distribuez le jeton partagé sur tous les nœuds de l'application.

      {{< tabs >}}

      {{< tab title="`incoming_email`" >}}

      ```ruby
      gitlab_rails['incoming_email_delivery_method'] = "webhook"

      # The URL that mail_room can contact. You can also use an internal URL or IP,
      # just make sure mail_room can access the GitLab API with that address.
      # Do not end with "/".
      gitlab_rails['incoming_email_gitlab_url'] = "https://gitlab.example.com"

      # The shared secret file that should contain a random token. Make sure it's the same on every node.
      gitlab_rails['incoming_email_secret_file'] = ".gitlab_mailroom_secret"
      ```

      {{< /tab >}}

      {{< tab title="`service_desk_email`" >}}

      ```ruby
      gitlab_rails['service_desk_email_delivery_method'] = "webhook"

      # The URL that mail_room can contact. You can also use an internal URL or IP,
      # just make sure mail_room can access the GitLab API with that address.
      # Do not end with "/".

      gitlab_rails['service_desk_email_gitlab_url'] = "https://gitlab.example.com"

      # The shared secret file that should contain a random token. Make sure it's the same on every node.
      gitlab_rails['service_desk_email_secret_file'] = ".gitlab_mailroom_secret"
      ```

      {{< /tab >}}

      {{< /tabs >}}

   1. Si vous rencontrez des problèmes avec la configuration `webhook`, utilisez `sidekiq` pour livrer le contenu de l'e-mail directement à GitLab Sidekiq via Redis.

      {{< tabs >}}

      {{< tab title="`incoming_email`" >}}

      ```ruby
      # It uses the Redis configuration to directly add Sidekiq jobs
      gitlab_rails['incoming_email_delivery_method'] = "sidekiq"
      ```

      {{< /tab >}}

      {{< tab title="`service_desk_email`" >}}

      ```ruby
      # It uses the Redis configuration to directly add Sidekiq jobs
      gitlab_rails['service_desk_email_delivery_method'] = "sidekiq"
      ```

      {{< /tab >}}

      {{< /tabs >}}

1. Désactivez `mail_room` sur tous les nœuds qui ne doivent pas exécuter l'ingestion d'e-mails. Par exemple, dans `/etc/gitlab/gitlab.rb` :

   ```ruby
   mailroom['enable'] = false
   ```

1. [Reconfigurez GitLab](../../../administration/restart_gitlab.md) pour que les modifications prennent effet.

#### Configurer un nœud d'ingestion d'e-mails unique {#set-up-a-single-email-ingestion-node}

Après avoir configuré tous les nœuds et désactivé le processus `mail_room`, activez `mail_room` sur un seul nœud. Ce nœud interroge régulièrement les boîtes de réception `incoming_email` et `service_desk_email` et transfère les nouveaux e-mails non lus vers GitLab.

1. Choisissez un nœud existant qui prend également en charge l'ingestion d'e-mails.
1. Ajoutez la [configuration complète et les identifiants](../../../administration/incoming_email.md#configuration-examples) pour `incoming_email` et `service_desk_email`.
1. Activez `mail_room` sur ce nœud. Par exemple, dans `/etc/gitlab/gitlab.rb` :

   ```ruby
   mailroom['enable'] = true
   ```

1. [Reconfigurez GitLab](../../../administration/restart_gitlab.md) sur ce nœud pour que les modifications prennent effet.

## Désactiver le Service d'assistance pour plusieurs projets {#turn-off-service-desk-for-multiple-projects}

Pour désactiver le Service d'assistance dans de nombreux projets d'un espace de nommage, utilisez l'[API](../../../api/projects.md#turn-off-service-desk-for-multiple-projects) ou, sur GitLab Self-Managed, la [console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session).

Après avoir désactivé le Service d'assistance pour les projets d'un groupe ou d'un espace de nommage, les règles suivantes s'appliquent :

- Les membres du projet peuvent réactiver le Service d'assistance.
- Les projets que vous créerez ultérieurement auront le Service d'assistance activé par défaut.

> [!warning]
> Les commandes qui modifient des données peuvent causer des dommages si elles ne sont pas exécutées correctement ou dans les bonnes conditions. Exécutez toujours les commandes dans un environnement de test en premier et disposez d'une instance de sauvegarde prête à être restaurée.

Pour désactiver le Service d'assistance pour tous les projets d'un espace de nommage, exécutez les commandes suivantes. Remplacez `my-namespace` par le chemin complet d'un groupe ou d'un espace de nommage personnel.

```ruby
namespace = Namespace.find_by_full_path!('my-namespace')
scope = namespace.is_a?(Group) ? namespace.all_projects : namespace.projects

scope.where(service_desk_enabled: true).each_batch(of: 100) do |batch|
  batch.update_all(service_desk_enabled: false)
end
```

Pour maintenir le Service d'assistance actif pour certains projets, excluez leurs identifiants de projet :

```ruby
keep_ids = [42, 1337]
namespace = Namespace.find_by_full_path!('my-namespace')
scope = namespace.is_a?(Group) ? namespace.all_projects : namespace.projects

scope.where(service_desk_enabled: true).where.not(id: keep_ids).each_batch(of: 100) do |batch|
  batch.update_all(service_desk_enabled: false)
end
```
