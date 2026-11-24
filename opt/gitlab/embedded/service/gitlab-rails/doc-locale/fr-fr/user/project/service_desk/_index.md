---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Service Desk
description: "Utilisez Service Desk pour recevoir les rapports de bugs, les demandes de fonctionnalités et les retours de vos clients par e-mail sous forme de tickets GitLab, sans nécessiter de comptes GitLab clients."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!note]
> Cette fonctionnalité n'est pas en cours de développement actif, mais les [contributions de la communauté](https://about.gitlab.com/community/contribute/) sont les bienvenues. Pour déterminer si la fonctionnalité telle qu'elle est répond à vos besoins, explorez la documentation existante ou consultez les [tickets ouverts pour la catégorie Service Desk](https://gitlab.com/gitlab-org/gitlab/-/issues/?sort=updated_desc&state=opened&label_name%5B%5D=Category%3AService%20Desk&first_page_size=100) pour en savoir plus sur les travaux qui n'ont pas encore été réalisés. La décision de déprioriser Service Desk a été prise afin de se concentrer sur la création et l'extension du framework des éléments de travail, dont la catégorie Service Desk bénéficie également sur le long terme.
>
> Pour obtenir des informations sur l'intégration de Service Desk dans le framework des éléments de travail, consultez l'[epic 10772](https://gitlab.com/groups/gitlab-org/-/epics/10772).

Avec Service Desk, vos clients peuvent vous envoyer par e-mail des rapports de bugs, des demandes de fonctionnalités ou des retours généraux. Service Desk fournit une adresse e-mail unique, de sorte qu'ils n'ont pas besoin de leur propre compte GitLab.

Les e-mails Service Desk sont créés dans votre projet GitLab sous forme de nouveaux tickets. Votre équipe peut répondre directement depuis le projet, tandis que les clients interagissent avec le fil de discussion uniquement par e-mail.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une présentation vidéo, consultez [Introducing GitLab Service Desk](https://www.youtube.com/watch?v=LDVQXv3I5rI).
<!-- Video published on 2023-12-19 -->

## Workflow Service Desk {#service-desk-workflow}

Par exemple, supposons que vous développiez un jeu pour iOS ou Android. La base de code est hébergée dans votre instance GitLab, construite et déployée avec GitLab CI/CD.

Voici comment Service Desk fonctionne pour vous :

1. Vous fournissez une adresse e-mail spécifique au projet à vos clients payants, qui peuvent vous envoyer des e-mails directement depuis l'application.
1. Chaque e-mail qu'ils envoient crée un ticket dans le projet approprié.
1. Les membres de votre équipe accèdent au tracker de tickets Service Desk, où ils peuvent voir les nouvelles demandes d'assistance et répondre dans les tickets associés.
1. Votre équipe communique avec le client pour comprendre la demande.
1. Votre équipe commence à travailler sur l'implémentation du code pour résoudre le problème de votre client.
1. Lorsque votre équipe termine l'implémentation, la merge request est fusionnée et le ticket est fermé automatiquement.

Entre-temps :

- Le client interagit avec votre équipe entièrement par e-mail, sans avoir besoin d'accéder à votre instance GitLab.
- Votre équipe gagne du temps en n'ayant pas à quitter GitLab (ni à configurer des intégrations) pour assurer le suivi avec votre client.

## Sujets connexes {#related-topics}

- [Configurer Service Desk](configure.md)
  - [Améliorer la sécurité de votre projet](configure.md#improve-your-projects-security)
  - [Personnaliser les e-mails envoyés aux participants externes](configure.md#customize-emails-sent-to-external-participants)
  - [Utiliser un modèle personnalisé pour les tickets Service Desk](configure.md#use-a-custom-template-for-service-desk-tickets)
  - [Utilisateur bot de support](configure.md#support-bot-user)
  - [Visibilité des tickets par défaut](configure.md#default-ticket-visibility)
  - [Rouvrir les tickets lorsqu'un participant externe commente](configure.md#reopen-tickets-when-an-external-participant-comments)
  - [Adresse e-mail personnalisée](configure.md#custom-email-address)
  - [Utiliser un alias e-mail Service Desk supplémentaire](configure.md#use-an-additional-service-desk-alias-email)
  - [Configurer l'ingestion d'e-mails dans les environnements multi-nœuds](configure.md#configure-email-ingestion-in-multi-node-environments)
- [Utiliser Service Desk](using_service_desk.md)
  - [En tant qu'utilisateur final (créateur de ticket)](using_service_desk.md#as-an-end-user-ticket-creator)
  - [En tant que répondant au ticket](using_service_desk.md#as-a-responder-to-the-ticket)
  - [Contenu et mise en forme des e-mails](using_service_desk.md#email-contents-and-formatting)
  - [Convertir un ticket standard en ticket Service Desk](using_service_desk.md#convert-a-regular-issue-to-a-service-desk-ticket)
  - [Considérations relatives à la confidentialité](using_service_desk.md#privacy-considerations)
- [Participants externes](external_participants.md)
  - [Tickets Service Desk](external_participants.md#service-desk-tickets)
  - [En tant que participant externe](external_participants.md#as-an-external-participant)
  - [En tant qu'utilisateur GitLab](external_participants.md#as-a-gitlab-user)

## Dépannage de Service Desk {#troubleshooting-service-desk}

### Les e-mails envoyés à Service Desk ne créent pas de tickets {#emails-to-service-desk-do-not-create-tickets}

- Vos e-mails peuvent être ignorés parce qu'ils contiennent l'un des [en-têtes d'e-mail que GitLab ignore](../../../administration/incoming_email.md#rejected-headers).
- Les e-mails peuvent être rejetés si le domaine d'e-mail de l'expéditeur utilise des règles DKIM strictes et qu'une vérification échoue en raison de la redirection des e-mails vers l'adresse Service Desk spécifique au projet. Un message d'échec DKIM typique, qui peut être trouvé dans les en-têtes d'e-mail, peut ressembler à :

  ```plaintext
  dkim=fail (signature did not verify) ... arc=fail
  ```

  Le libellé exact du message d'échec peut varier selon le système d'e-mail ou les outils utilisés. Consultez également [cet article sur les échecs DKIM](https://automatedemailwarmup.com/blog/dkim-fail/) pour plus d'informations et des solutions potentielles.

### L'ingestion d'e-mails ne fonctionne pas dans la version 16.6.0 {#email-ingestion-doesnt-work-in-1660}

GitLab Self-Managed `16.6.0` a introduit une régression qui empêche `mail_room` (ingestion d'e-mails) de démarrer. Service Desk et les autres fonctionnalités de réponse par e-mail ne fonctionnent pas. Le [ticket 432257](https://gitlab.com/gitlab-org/gitlab/-/issues/432257) suit la résolution de ce problème.

La solution de contournement consiste à exécuter les commandes suivantes dans votre installation GitLab pour corriger les fichiers concernés :

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

```shell
curl --output /tmp/mailroom.patch --url "https://gitlab.com/gitlab-org/gitlab/-/merge_requests/137279.diff"
patch -p1 -d /opt/gitlab/embedded/service/gitlab-rails < /tmp/mailroom.patch
gitlab-ctl restart mailroom
```

{{< /tab >}}

{{< tab title="Docker" >}}

```shell
curl --output /tmp/mailroom.patch --url "https://gitlab.com/gitlab-org/gitlab/-/merge_requests/137279.diff"
cd /opt/gitlab/embedded/service/gitlab-rails
patch -p1 < /tmp/mailroom.patch
gitlab-ctl restart mailroom
```

{{< /tab >}}

{{< /tabs >}}
