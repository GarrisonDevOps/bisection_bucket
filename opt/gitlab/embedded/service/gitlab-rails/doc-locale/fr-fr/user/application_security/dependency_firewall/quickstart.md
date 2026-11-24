---
stage: Security Risk Management
group: Pipeline Security
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Commencer avec le pare-feu de dépendances
description: "Activez le pare-feu de dépendances, ajoutez une politique en mode d'avertissement et vérifiez les résultats."
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed
- Statut : version bêta

{{< /details >}}

Configurez le pare-feu de dépendances et consultez son premier résultat. Vous activez le pare-feu, ajoutez une politique qui signale les correspondances sans les bloquer, installez un paquet et lisez ce que le pare-feu a détecté.

La politique de ce guide utilise le mode `warn`, de sorte que rien n'est bloqué pendant que vous l'essayez. La dernière étape couvre le passage à l'application.

Prévoyez environ 15 minutes.

Prérequis :

- Votre espace de nommage doit avoir accès à l'édition Premium ou Ultimate.
- Sur GitLab.com, vous devez avoir le rôle Propriétaire pour le groupe principal. Sur GitLab Self-Managed, vous devez être administrateur.
- Vous avez besoin d'un projet avec un gestionnaire de paquets pris en charge par cette fonctionnalité. Ce guide utilise npm.

## Étape 1 :  activer le pare-feu {#step-1-turn-on-the-firewall}

Sur GitLab.com :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Sélectionnez **Paramètres** > **Sécuriser**.
1. Activez le bouton **Activer le pare-feu de dépendances**.

Sur GitLab Self-Managed :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Sélectionnez **Paramètres** > **Sécurité et conformité**.
1. Développez **Pare-feu de dépendances**.
1. Cochez la case **Activer le pare-feu de dépendances**, puis sélectionnez **Enregistrer les modifications**.

Rien n'est encore évalué. Le pare-feu a besoin d'une politique, que vous allez ajouter ensuite.

## Étape 2 :  ajouter une politique en mode d'avertissement {#step-2-add-a-policy-in-warn-mode}

Les politiques résident dans un [projet de politique de sécurité](../policies/enforcement/security_policy_projects.md). Si votre groupe n'en possède pas, GitLab en crée un lorsque vous enregistrez votre première politique.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Sélectionnez **Sécurisation** > **Politiques**.
1. Sélectionnez **Nouvelle politique**.
1. Dans **Politique de pare-feu de dépendances**, sélectionnez **Sélectionner la politique**.
   <!-- markdownlint-disable-next-line MD044 -->
1. L'éditeur s'ouvre en mode règle, sous forme de formulaire. Pour coller la politique à la place, sélectionnez **Mode .yaml**.
1. Remplacez le contenu de l'éditeur par la politique suivante :

   ```yaml
   dependency_firewall_policy:
     - name: Audit high-risk packages
       description: Reports packages with critical vulnerabilities or malicious code.
       enabled: true
       enforcement_type: warn
       rules:
         - type: risk_severity
           denied:
             # threshold is the number of vulnerabilities you permit.
             # 0 permits none, so a single critical vulnerability matches.
             - severity: critical
               threshold: 0
         - type: malicious
           denied:
             - is_malicious: true
   ```

1. Sélectionnez **Configurer avec une requête de fusion**.
1. Examinez et fusionnez la merge request.

Cette politique signale tout paquet portant une vulnérabilité critique ou signalé comme malveillant. Comme `enforcement_type` est défini sur `warn`, rien n'est bloqué.

## Étape 3 :  installer un paquet via le pare-feu {#step-3-install-a-package-through-the-firewall}

Les politiques sont évaluées par la [CLI GitLab](../../../editor_extensions/gitlab_cli/_index.md), donc installez-la et authentifiez-la d'abord :

```shell
glab auth login
```

Clonez le projet auquel la politique s'applique, puis installez ses dépendances avec `glab df` devant votre commande habituelle :

```shell
git clone https://gitlab.example.com/my-group/my-project.git
cd my-project
glab df npm install
```

`npm` s'exécute comme d'habitude. La CLI vérifie chaque paquet qu'elle résout par rapport à votre politique.

## Étape 4 :  lire le résultat {#step-4-read-the-result}

Une fois `npm` terminé, la CLI affiche ce que le pare-feu a détecté :

```plaintext
╭──────────────────────────────────────────────────────────────────────────────────╮
│ ▲  GitLab Dependency Firewall                                                    │
│ 1 package warning                                                                │
├──────────────────────────────────────────────────────────────────────────────────┤
│    PACKAGE  VERSION  REASON                                                      │
│ ▲  lodash   4.17.15  Package 'lodash' violates 'Audit high-risk packages' policy │
╰──────────────────────────────────────────────────────────────────────────────────╯
```

Un `▲` marque un paquet ayant reçu un avertissement. Si la politique avait été en mode `enforced`, ce paquet aurait affiché un `✖` à la place, et `npm` aurait échoué.

Si aucun récapitulatif n'est affiché, aucun paquet ne correspond à votre politique. Essayez `glab df npm install lodash@4.17.15`, qui présente des vulnérabilités connues, pour voir une correspondance.

> [!tip]
> Pour vérifier un paquet sans l'installer, exécutez `glab df package pkg:npm/lodash@4.17.15`. Pour plus d'informations, consultez [`glab dependency-firewall package`](https://docs.gitlab.com/cli/dependency-firewall/package/).

Pour voir les mêmes résultats dans GitLab, sélectionnez **Sécuriser** > **Pare-feu de dépendances** dans votre groupe ou projet. Le tableau de bord comptabilise ce qui a été bloqué et averti, et liste chaque règle active.

## Étape 5 :  passer à l'application {#step-5-switch-to-enforcement}

Lorsque les avertissements correspondent à ce que vous souhaitez bloquer, modifiez la politique pour les appliquer :

1. Sélectionnez **Sécurisation** > **Politiques**.
1. Dans la ligne de la politique, sélectionnez **Modifier**.
   <!-- markdownlint-disable-next-line MD044 -->
1. Pour **Mode d'application**, sélectionnez **Imposer**. En **Mode .yaml**, définissez `enforcement_type` sur `enforced`.
1. Sélectionnez **Configurer avec une requête de fusion**, puis révisez-la et fusionnez-la.

Les paquets correspondants sont désormais refusés. Le gestionnaire de paquets reçoit une réponse `403 Forbidden` et l'installation échoue, ce qui empêche le paquet d'atteindre la machine ou le pipeline.

Déployez l'application progressivement. Utilisez [`policy_scope`](_index.md#policy-scope) pour appliquer d'abord une politique à quelques projets, et les [paramètres de contournement](_index.md#bypass-settings) pour exempter un compte de service qui doit continuer à publier.

## Étapes suivantes {#next-steps}

- Ajoutez des règles pour les [licences](_index.md#license-rules), ou ajustez les [seuils de gravité des risques](_index.md#risk-severity-rules).
- Exécutez le pare-feu en CI/CD avec [`glab df` dans vos scripts de job](_index.md#use-the-dependency-firewall-in-cicd).
