---
stage: Security Risk Management
group: Security Policies
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 'Tutoriel : configurer une politique d''approbation des merge requests'
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Ce tutoriel vous montre comment créer et configurer une [politique d'approbation des merge requests](../../user/application_security/policies/merge_request_approval_policies.md). Ces politiques peuvent être configurées pour effectuer des actions en fonction des résultats d'analyse. Par exemple, dans ce tutoriel, vous allez configurer une politique qui exige l'approbation de deux utilisateurs spécifiés si une vulnérabilité est détectée dans une merge request.

Pour configurer une politique d'approbation des merge requests :

1. [Créer un projet de test](#create-a-test-project).
1. [Ajouter une politique d'approbation des merge requests](#add-a-merge-request-approval-policy).
1. [Tester la politique d'approbation des merge requests](#test-the-merge-request-approval-policy).

## Avant de commencer {#before-you-begin}

- L'espace de nommage que vous utilisez pour ce tutoriel doit contenir au minimum trois utilisateurs, y compris vous-même. Si vous ne disposez pas de deux autres utilisateurs, vous devez d'abord les créer. Pour plus de détails, consultez [Créer des utilisateurs](../../user/profile/account/create_accounts.md).
- Vous devez disposer de la permission de créer de nouveaux projets dans un groupe existant.

## Créer un projet de test {#create-a-test-project}

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer un projet vide**.
1. Remplissez les champs.
   - **Nom du projet** : `sast-scan-result-policy`.
   - Cochez la case **Activer les tests statiques de sécurité des applications (SAST)**.
1. Sélectionnez **Créer le projet**.
1. Pour protéger la branche par défaut :
   1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et saisissez `sast-scan-result-policy`.
   1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
   1. Développez **Règles des branches**.
   1. Sélectionnez **Ajouter une règle de branche** > **Schéma ou nom de la branche**.
   1. Dans la liste déroulante, recherchez et sélectionnez `main` (ou votre branche par défaut), puis sélectionnez **Créer une règle de branche**.
   1. Dans la section **Autorisés à fusionner**, sélectionnez **Modifier**, définissez-la sur **Chargés de maintenance**, puis sélectionnez **Enregistrer les modifications**.
   1. Dans la section **Autorisés à pousser et fusionner**, sélectionnez **Modifier**, définissez-la sur **Personne**, puis sélectionnez **Enregistrer les modifications**.

## Ajouter une politique d'approbation des merge requests {#add-a-merge-request-approval-policy}

Ensuite, vous allez ajouter une politique d'approbation des merge requests à votre projet de test :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet `sast-scan-result-policy`.
1. Sélectionnez **Sécurisation** > **Politiques**.
1. Sélectionnez **Nouvelle politique**.
1. Dans **Stratégie d'approbation des requêtes de fusion**, sélectionnez **Sélectionner la politique**.
1. Remplissez les champs.
   - **Nom** : `sast-scan-result-policy`
   - **État de la politique** : **Activé**
1. Sélectionnez **Ajouter une règle** et configurez la règle :
   - Pour le type d'analyse, sélectionnez **analyse de sécurité** avec **SAST**.
   - Pour la cible, sélectionnez **toutes les branches protégées** avec **aucune exception**.
   - Pour le nombre de vulnérabilités, sélectionnez **plus de** et saisissez `0`.
1. Sous **Paramètres généraux**, configurez la gravité et le statut :
   - **La gravité est** : **Tous les niveaux de gravité**
   - **Statut** : **Nouvelle** + **Tous les états de vulnérabilité**

1. Définissez **Actions** comme suit :

   ```plaintext
   THEN Require approval from | 2 | of the following approvers:
   ```

1. Sélectionnez deux utilisateurs.
1. Sélectionnez **Configurer avec une requête de fusion**.

   L'application crée un nouveau projet pour stocker les politiques qui lui sont associées, et crée une merge request pour définir la politique.
1. Sélectionnez **Fusionner**.
1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet `sast-scan-result-policy`.
1. Sélectionnez **Sécurisation** > **Politiques**.

   Vous pouvez voir la liste des politiques ajoutées lors des étapes précédentes.

## Tester la politique d'approbation des merge requests {#test-the-merge-request-approval-policy}

Bravo, vous avez créé une politique d'approbation des merge requests. Pour la tester, créez quelques vulnérabilités et vérifiez le résultat :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet `sast-scan-result-policy`.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Dépôt**.
1. Dans la liste déroulante **Ajouter** ({{< icon name="plus" >}}), sélectionnez **Nouveau fichier**.
1. Dans le champ **Nom du fichier**, saisissez `main.ts`.
1. Dans le contenu du fichier, copiez ce qui suit :

   ```typescript
   // Non-literal require - tsr-detect-non-literal-require
   var lib: String = 'fs'
   require(lib)

   // Eval with variable - tsr-detect-eval-with-expression
   var myeval: String = 'console.log("Hello.");';
   eval(myeval);

   // Unsafe Regexp - tsr-detect-unsafe-regexp
   const regex: RegExp = /(x+x+)+y/;

   // Non-literal Regexp - tsr-detect-non-literal-regexp
   var myregexpText: String = "/(x+x+)+y/";
   var myregexp: RegExp = new RegExp(myregexpText);
   myregexp.test("(x+x+)+y");

   // Markup escaping disabled - tsr-detect-disable-mustache-escape
   var template: Object = new Object;
   template.escapeMarkup = false;

   // Detects HTML injections - tsr-detect-html-injection
   var element: Element =  document.getElementById("mydiv");
   var content: String = "mycontent"
   Element.innerHTML = content;

   // Timing attack - tsr-detect-possible-timing-attacks
   var userInput: String = "Jane";
   var auth: String = "Jane";
   if (userInput == auth) {
     console.log(userInput);
   }
   ```

1. Dans le champ **Message de commit**, saisissez `Add vulnerable file`.
1. Dans le champ **Branche cible**, saisissez `test-branch`.
1. Sélectionnez **Valider les modifications**. Le formulaire **Nouvelle requête de fusion** s'ouvre.
1. Sélectionnez **Créer une requête de fusion**.
1. Dans la nouvelle merge request, sélectionnez `Create merge request`.

   Attendez que le pipeline se termine. Cela peut prendre quelques minutes.

L'onglet **Rapports** de la merge request confirme que l'analyse de sécurité a détecté une vulnérabilité potentielle. Comme défini dans la politique d'approbation des merge requests, la merge request est bloquée et en attente d'approbation.

Vous savez désormais comment configurer et utiliser les politiques d'approbation des merge requests pour détecter les vulnérabilités !
