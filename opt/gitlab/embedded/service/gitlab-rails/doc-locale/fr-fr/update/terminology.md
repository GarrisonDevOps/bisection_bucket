---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Termes de dépréciation
---

## Dépréciation {#deprecation}

- Obligatoire avant d'arrêter la prise en charge d'une fonctionnalité ou de la supprimer.
- Fonctionnalité déconseillée.
- Développement limité aux corrections de bugs de priorité 1 / gravité 1.
- Sera supprimée dans une future version majeure.
- Commence après une annonce de dépréciation précisant une date de fin de prise en charge ou de suppression.
- Se termine après que la date de fin de prise en charge ou de suppression est passée.

## Fin de prise en charge {#end-of-support}

- Étape facultative avant la suppression.
- Utilisation de la fonctionnalité fortement déconseillée.
- Aucune assistance ni correction fournie.
- N'est plus testée en interne.
- Sera supprimée dans une future version majeure.
- Commence après qu'une date de fin de prise en charge est passée.

L'annonce d'une période de fin de prise en charge ne doit être utilisée que dans des circonstances particulières et n'est pas recommandée pour un usage général. La plupart des fonctionnalités doivent être dépréciées puis supprimées.

## Suppression {#removal}

- Utilisation de la fonctionnalité impossible.
- Fonctionnalité qui n'est plus prise en charge (si la période de fin de prise en charge n'a pas déjà été annoncée).
- S'effectue dans une version majeure conformément à notre [politique de gestion sémantique de version](../policy/maintenance.md).
- Commence après que la date de suppression est passée.

## Changement cassant {#breaking-change}

Tout changement est considéré comme un changement cassant si les clients doivent prendre des mesures pour s'assurer que leurs workflows GitLab ne sont pas perturbés.

Un changement cassant peut provenir de sources telles que :

- Un changement de produit intentionnel
- Une mise à jour de configuration
- Une dépréciation tierce

Par défaut, aucun changement cassant n'est autorisé sauf si le plan d'implémentation du changement cassant a été approuvé par la direction.

## Dépendances tierces {#third-party-dependencies}

Cette section s'applique à tous les termes précédents.

Les changements (dépréciation, fin de prise en charge, suppression ou changement cassant) dans les dépendances tierces sont traités séparément des changements apportés aux fonctionnalités de GitLab lui-même :

- Ces changements suivent le cycle de vie propre à la dépendance et ne sont pas soumis aux exigences de processus et de calendrier des fonctionnalités pour GitLab.
- GitLab s'efforce de minimiser l'impact et de fournir une expérience de migration fluide pour les changements de dépendances tierces qui affectent notre produit.
- Les mises à jour de sécurité des dépendances peuvent être appliquées sans suivre leurs processus de dépréciation standard lorsque cela est nécessaire pour traiter des vulnérabilités graves dans les délais de résolution des vulnérabilités définis par les SLA. Pour plus d'informations, consultez le Manuel GitLab.
- Dans les cas où les dépendances changent en dehors de notre contrôle ou de notre calendrier, GitLab peut avoir besoin d'implémenter des changements dans ses propres logiciels en dehors de son processus et de son calendrier habituels pour maintenir ses fonctionnalités, sa compatibilité ou sa sécurité.
- GitLab fera des efforts raisonnables pour communiquer les changements significatifs de dépendances tierces.
- GitLab n'est pas responsable des changements dans les fonctionnalités des dépendances tierces qui ne sont pas directement utilisées par les produits GitLab.
- Les clients qui utilisent ces dépendances tierces au-delà des schémas d'utilisation de GitLab le font à leurs propres risques et doivent :
  - Surveiller de manière indépendante les notes de release du tiers.
  - Tester leurs implémentations personnalisées par rapport aux nouvelles versions des dépendances.
  - Planifier leurs propres stratégies de migration pour les changements tiers.
