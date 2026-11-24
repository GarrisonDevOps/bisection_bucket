---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Remédier
description: "Corriger ou éliminer la cause racine d'une vulnérabilité."
---

La remédiation est la quatrième phase du cycle de vie de la gestion des vulnérabilités : détecter, trier, analyser, remédier.

La remédiation est le processus de correction ou d'élimination de la cause racine d'une vulnérabilité. Utilisez les informations contenues dans la [page de détails](../vulnerabilities/_index.md) de chaque vulnérabilité pour vous aider à comprendre la nature de la vulnérabilité et à y remédier.

<i class="fa-youtube-play"></i> Pour une présentation de la façon dont GitLab Duo peut vous aider à analyser une vulnérabilité et à y remédier, consultez [Use GitLab Duo to remediate an SQL injection](https://youtu.be/EJXAIzXNAWQ?si=IDKtApBH1j5JwdUY).

## Portée {#scope}

La portée de la phase de remédiation englobe toutes les vulnérabilités ayant traversé la phase d'analyse et confirmées comme nécessitant une action supplémentaire. Pour répertorier ces vulnérabilités, utilisez les critères de filtre suivants dans le rapport de vulnérabilités :

- **Statut** : Confirmé
- **Activité** : a un ticket

## Documenter la vulnérabilité {#document-the-vulnerability}

Si vous ne l'avez pas encore fait, [créez un ticket](../vulnerabilities/_index.md#create-a-gitlab-issue-for-a-vulnerability) pour documenter votre investigation et votre travail de remédiation. Suivez ces étapes si cette vulnérabilité se reproduit ou si vous trouvez des vulnérabilités similaires.

## Choisir un résultat {#choose-an-outcome}

Après avoir analysé une vulnérabilité, vous devez décider de la corriger ou de la rejeter. Utilisez le cadre de gestion des risques de votre organisation pour guider votre décision. Les recommandations présentées ici sont génériques. Adaptez-les au profil de risque de votre organisation.

Si disponible, utilisez l'[agent Security Analyst](../../duo_agent_platform/agents/foundational_agents/security_analyst_agent.md) pour accélérer la remédiation des vulnérabilités. L'agent trie, évalue et remédie aux résultats de sécurité en fournissant des informations, des évaluations des risques et des recommandations de remédiation.

Remédiez à une vulnérabilité dans les cas suivants :

- La vulnérabilité représente un risque de sécurité réel dans votre environnement.
- La cause racine peut être corrigée ou atténuée.
- L'effort requis est justifié par le niveau de risque.

Rejetez une vulnérabilité dans les cas suivants :

- Le coût estimé de l'effort de remédiation est trop élevé.
- La vulnérabilité présente peu ou pas de risque.
- Le risque lié à la vulnérabilité a déjà été atténué.
- La vulnérabilité n'est pas valide dans votre environnement.

## Remédier à une vulnérabilité {#remediate-a-vulnerability}

Utilisez les informations recueillies lors de la phase d'analyse pour vous guider dans la remédiation de la vulnérabilité. Il est important de comprendre la cause racine de la vulnérabilité pour que la remédiation soit efficace.

Modifiez le statut d'une vulnérabilité en **Résolue** lorsque vous y avez remédié. Ce changement de statut crée un enregistrement indiquant quand et comment la vulnérabilité a été traitée, ce qui est important pour la conformité et les révisions de sécurité. Si la même vulnérabilité est à nouveau détectée lors de futures analyses, GitLab réintègre automatiquement l'enregistrement et remet son statut à **Nécessite un classement**, vous alertant d'une régression.

Prérequis :

- Le rôle Responsable sécurité, Chargé de maintenance ou Propriétaire pour le projet.

Pour modifier le statut d'une vulnérabilité en résolue :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Rapport de vulnérabilités**.
1. Trouvez la vulnérabilité dans le rapport de vulnérabilités.
1. Sélectionnez la description de la vulnérabilité.
1. Dans la barre latérale droite, dans la section **Statut**, sélectionnez **Modifier**.
1. Dans la liste déroulante **Statut**, sélectionnez **Résolue**.
1. Facultatif. Dans la zone de saisie **Commentaire**, expliquez pourquoi vous avez marqué la vulnérabilité comme résolue.
1. Sélectionnez **Modifier le statut**.
1. Si vous avez créé un ticket pour la vulnérabilité, documentez la façon dont elle a été remédiée, puis fermez le ticket.

## Rejeter une vulnérabilité {#dismiss-a-vulnerability}

Modifiez le statut d'une vulnérabilité en **Rejetée** lorsque vous avez décidé que la remédiation n'est pas justifiée. Ce changement de statut crée un enregistrement indiquant quand et comment la vulnérabilité a été traitée, ce qui est important pour la conformité et les révisions de sécurité. Une vulnérabilité rejetée est ignorée si elle est détectée lors d'analyses ultérieures.

Prérequis :

- Le rôle Responsable sécurité, Chargé de maintenance ou Propriétaire pour le projet.

Pour rejeter une vulnérabilité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Rapport de vulnérabilités**.
1. Trouvez la vulnérabilité dans le rapport de vulnérabilités.
1. Sélectionnez la description de la vulnérabilité.
1. Dans la barre latérale droite, dans la section **Statut**, sélectionnez **Modifier**.
1. Dans la liste déroulante **Statut**, sélectionnez un motif de rejet.
1. Dans la zone de saisie **Commentaire**, expliquez pourquoi vous avez rejeté la vulnérabilité.
1. Sélectionnez **Modifier le statut**.
1. Si vous avez créé un ticket pour la vulnérabilité, documentez les raisons pour lesquelles vous l'avez rejetée, puis fermez le ticket.
