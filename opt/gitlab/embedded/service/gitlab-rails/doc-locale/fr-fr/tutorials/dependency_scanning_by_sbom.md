---
stage: Application Security Testing
group: Composition Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Apprenez à configurer l'analyse des dépendances à l'aide de SBOM, à détecter les vulnérabilités dans les dépendances de votre projet et à comprendre quelles vulnérabilités sont accessibles dans votre code."
title: 'Tutoriel : configurer l''analyse des dépendances à l''aide de SBOM'
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

L'analyse des dépendances peut détecter automatiquement les vulnérabilités de sécurité dans les dépendances de vos logiciels avant qu'elles ne soient commitées dans votre branche principale. Pendant le développement et le test de vos applications, vous pouvez identifier et corriger les dépendances vulnérables tôt dans votre workflow. L'analyseur de dépendances génère une nomenclature logicielle (SBOM) des dépendances de votre application, puis les compare aux avis de sécurité pour identifier les vulnérabilités. L'analyse de l'accessibilité statique améliore les données d'évaluation des risques liés aux vulnérabilités en identifiant quelles dépendances vulnérables votre application importe.

Ce tutoriel vous explique comment effectuer les opérations suivantes :

- Créer un exemple d'application JavaScript.
- Configurer l'analyse des dépendances à l'aide du nouvel analyseur SBOM, y compris l'analyse de l'accessibilité statique.
- Trier les vulnérabilités dans les dépendances de l'application.
- Remédier à une vulnérabilité en mettant à jour une dépendance.

> [!note]
> Ce tutoriel utilise des dépendances obsolètes avec des vulnérabilités connues pour démontrer la détection.

## Avant de commencer {#before-you-begin}

Avant de commencer ce tutoriel, assurez-vous de disposer des éléments suivants :

- Un compte GitLab.com et l'accès nécessaire pour créer un nouveau projet
- Git
- Node.js (version 14 ou ultérieure)

## Créer les fichiers de l'exemple d'application {#create-example-application-files}

La première tâche de ce tutoriel consiste à configurer l'exemple de projet, y compris l'exemple d'application vulnérable, et à configurer CI/CD.

1. Sur GitLab.com, créez un projet vide en utilisant les valeurs par défaut.
1. Clonez le projet sur votre machine locale :

   ```plaintext
   git clone https://gitlab.com/<your-username>/<project-name>.git
   cd <project-name>
   ```

1. Sur votre machine locale, créez les fichiers suivants dans votre projet :

   - `.gitlab-ci.yml`
   - `package.json`
   - `app.js`

   Nom de fichier : `.gitlab-ci.yml`

   ```yaml
   stages:

   - build
   - test

   include:
   - template: Jobs/Dependency-Scanning.v2.gitlab-ci.yml
     inputs:
       enable_static_reachability: true
   ```

   Nom de fichier : `package.json`

   ```json
   {
      "name": "tutorial-ds-sbom-scanning-with-sra",
      "version": "1.0.0",
      "main": "index.js",
      "dependencies": {
         "axios": "0.21.1",
         "fastify": "2.14.1"
      }
   }
   ```

   Nom de fichier : `app.js`

   ```javascript
   const axios = require('axios');

   async function runDemo() {
     console.log("Starting Reachability Demo...");
     try {
       // This specific call creates the reachability link
       const response = await axios.get('<https://gitlab.com>');
       console.log("Request successful, status:", response.status);
     } catch (err) {
       console.log("Demo request finished.");
     }
   }

   runDemo();
   ```

1. Créez le fichier de verrouillage.

   ```plaintext
   npm install
   ```

1. Commitez et poussez ces fichiers vers votre projet :

   ```plaintext
   git add .gitlab-ci.yml app.js package.json package-lock.json
   git commit -m "Set up files for tutorial"
   git push
   ```

1. Sur GitLab.com, accédez à **Version** > **Pipelines** et confirmez que le dernier pipeline s'est terminé avec succès.

   Dans le pipeline, l'analyse des dépendances s'exécute et effectue les opérations suivantes :

   - Génère un SBOM à partir de vos dépendances. Vous pouvez [télécharger le SBOM](#optional-download-sbom).
   - Analyse les dépendances répertoriées dans le SBOM par rapport aux avis de vulnérabilités connus.
   - Enrichit les résultats grâce à l'analyse de l'accessibilité statique pour identifier quelles dépendances sont importées dans votre code.

## Trier et analyser les vulnérabilités {#triage-and-analyze-vulnerabilities}

L'analyse des dépendances devrait avoir détecté des vulnérabilités dans les dépendances de l'application. La prochaine tâche consiste à trier et analyser ces vulnérabilités.

> [!note]
> Pour simplifier ce tutoriel, toutes les modifications sont commitées dans la branche `main`. Dans un environnement réel, vous exécuteriez l'analyse des dépendances dans des branches de développement pour détecter les vulnérabilités avant la fusion de la branche.

Dans ce tutoriel, nous allons trier et analyser une seule vulnérabilité. Nous avons sélectionné cette vulnérabilité parce qu'elle est accessible et dispose d'un chemin de remédiation clair.

1. Sur GitLab.com, accédez à **Sécuriser** > **Rapport de vulnérabilités**.

   Vous devriez voir plusieurs vulnérabilités répertoriées dans le rapport. Au moment de la rédaction, 12 vulnérabilités avaient été détectées.

   > Pour les besoins de ce tutoriel, nous nous concentrerons sur une seule vulnérabilité. Dans un environnement réel, vous analyseriez toutes les [données d'évaluation des risques disponibles](../user/application_security/vulnerabilities/risk_assessment_data.md) et appliqueriez le cadre de gestion des risques de votre organisation.
1. Sélectionnez le filtre de recherche et dans la liste déroulante sélectionnez **Accessibilité**, puis sélectionnez **Oui**.

   Le rapport de vulnérabilités répertorie désormais uniquement les vulnérabilités accessibles. Le nombre de vulnérabilités par gravité est mis à jour pour correspondre au nouveau filtre.

   > Dans cet exemple, vous avez déclaré les dépendances directes suivantes dans `package.json` :
   >
   > - `axios` - version 0.21.1
   > - `fastify` - version 2.14.1
   >
   > L'analyse des dépendances a détecté des vulnérabilités dans `fastify` et `axios`, ainsi que dans leurs dépendances transitives. Cependant, seul `axios` est importé par l'exemple d'application, de sorte que les vulnérabilités dans `fastify` ne sont pas accessibles. Lorsque vous appliquez le filtre d'accessibilité, les vulnérabilités dans `fastify` sont exclues du rapport de vulnérabilités.

1. Sélectionnez la description de CVE-2026-25223 - « Fastify's Content-Type header tab character allows body validation bypass ».

   1. Consultez les détails de cette vulnérabilité.

      La vulnérabilité est de gravité élevée et a une valeur **Accessible** à **Oui**, ce qui signifie que la dépendance est importée par l'application. Cela la rend plus risquée que d'autres vulnérabilités de gravité élevée qui ne sont pas accessibles.

   1. Consultez la section **Remédiation**.

      Pour cette vulnérabilité, la solution consiste à mettre à niveau la version de cette dépendance.

Pour simplifier ce tutoriel, nous allons appliquer la solution indiquée. Dans un environnement réel, vous suivriez les processus d'analyse des vulnérabilités de votre entreprise pour vérifier cette solution avant de l'appliquer.

## Remédier à la vulnérabilité {#remediate-the-vulnerability}

Maintenant que nous avons une solution, nous allons procéder à la mise à niveau de la dépendance `fastify`.

1. Sur votre machine locale, mettez à jour le fichier `package.json` avec la version de `fastify` indiquée sur la page des détails de la vulnérabilité - 5.7.2.

   ```json
   {
      "name": "tutorial-ds-sbom-scanning-with-sra",
      "version": "1.0.0",
      "main": "index.js",
      "dependencies": {
         "axios": "0.21.1",
         "fastify": "5.7.2"
      }
   }
   ```

1. Mettez à jour le fichier de verrouillage.

   ```plaintext
   npm install
   ```

   Cela met à jour le fichier `package-lock.json` avec la nouvelle version de la dépendance.
1. Créez une nouvelle branche et commitez ces modifications :

   ```plaintext
   git checkout -b update-dependencies
   git add package.json package-lock.json
   git commit -m "Update version of fastify"
   git push -u origin update-dependencies
   ```

1. Sur GitLab.com, accédez à **Code** > **Requêtes de fusion** et sélectionnez **Créer une requête de fusion**.
1. Sur la page **Nouvelle requête de fusion**, faites défiler jusqu'en bas et sélectionnez **Créer une requête de fusion**.

   Une fois le pipeline de merge request terminé, attendez que le rapport d'analyse de sécurité apparaisse dans l'onglet **Rapports**. Le traitement du rapport de sécurité prend généralement une à deux minutes.
1. Sélectionnez l'onglet **Rapports**, puis sélectionnez **Analyse de sécurité**.

   Le rapport d'analyse de sécurité indique que les modifications apportées dans la merge request corrigent 7 vulnérabilités, y compris la vulnérabilité que vous avez triée et analysée.
1. Sélectionnez **Fusionner**.

   Attendez que la merge request soit fusionnée.
1. Accédez à **Sécurisation** > **Rapport de vulnérabilités**.

   La vulnérabilité CVE-2026-25223 n'est plus répertoriée car le rapport de vulnérabilités affiche par défaut uniquement les vulnérabilités dont la **Détection toujours active**. Pour consulter les détails de la vulnérabilité, vous pouvez modifier le filtre de statut.

Dans ce tutoriel, vous avez appris à effectuer les opérations suivantes :

- Configurer l'analyse des dépendances avec SBOM et l'analyse de l'accessibilité statique
- Détecter et trier les vulnérabilités dans vos dépendances
- Remédier aux vulnérabilités en mettant à jour les dépendances
- Vérifier que les vulnérabilités sont corrigées

## Facultatif : télécharger le SBOM {#optional-download-sbom}

Pour télécharger le SBOM généré par l'analyseur d'analyse des dépendances :

1. Accédez à **Version** > **Pipelines**.
1. Sélectionnez le pipeline le plus récent.
1. Sélectionnez le job **dependency-scanning**.
1. Dans la section **Artéfacts de job**, sélectionnez **Téléchargement**.

Les artefacts du job sont téléchargés sous forme de fichier `artifacts.zip`. Décompressez-le pour accéder au fichier SBOM `gl-sbom-npm-npm.cdx.json`.
