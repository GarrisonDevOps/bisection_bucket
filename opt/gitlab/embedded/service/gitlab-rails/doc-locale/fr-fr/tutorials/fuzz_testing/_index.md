---
stage: Application Security Testing
group: Dynamic Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 'Tutoriel : effectuer des tests d''injection de données aléatoires dans GitLab (obsolète)'
---

<!--- start_remove The following content will be removed on remove_date: '2026-12-31' -->

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> Le test fuzz guidé par la couverture a été [abandonné](https://gitlab.com/gitlab-org/gitlab/-/issues/517841) dans GitLab 18.0 et sa suppression est prévue dans la version 19.0. Il s'agit d'un changement majeur.

<!-- vale gitlab_base.FutureTense = NO -->

[Le test fuzz guidé par la couverture](../../user/application_security/coverage_fuzzing/_index.md#coverage-guided-fuzz-testing-process) envoie des données inattendues, malformées ou aléatoires à votre application, puis surveille les comportements instables et les plantages de votre application.

Cela vous aide à découvrir des bugs et des problèmes de sécurité potentiels que d'autres processus d'assurance qualité pourraient manquer.

Vous devriez utiliser le test fuzz en complément d'autres scanners de sécurité et de vos propres processus de test. Si vous utilisez GitLab CI/CD, vous pouvez exécuter des tests fuzz dans le cadre de votre workflow CI/CD.

Pour configurer et effectuer des tests fuzz guidés par la couverture à l'aide de JavaScript dans ce tutoriel, vous devez :

1. [Dupliquer le modèle de projet](#fork-the-project-template) pour créer un projet dans lequel exécuter les tests fuzz.
1. [Créer les cibles fuzz](#create-the-fuzz-targets).
1. [Activer le test fuzz guidé par la couverture](#enable-coverage-guided-fuzz-testing) dans votre projet dupliqué.
1. [Exécuter le test fuzz](#run-the-fuzz-test) pour identifier les vulnérabilités de sécurité.
1. [Corriger les vulnérabilités](#fix-the-vulnerabilities) identifiées par le test fuzz.

## Dupliquer le modèle de projet {#fork-the-project-template}

Pour commencer, afin de créer un projet dans lequel tester le test fuzz, vous devez dupliquer le modèle de projet `fuzz-testing` :

1. Ouvrez le [modèle de projet `fuzz-testing`](https://gitlab.com/gitlab-org/tutorial-project-templates/fuzz-testing).
1. [Dupliquez le modèle de projet](../../user/project/repository/forking_workflow.md).
1. Lors de la duplication du modèle de projet :
   - Nommez le projet dupliqué `fuzz-testing-demo`.
   - Sélectionnez un [espace de nommage](../../user/namespace/_index.md) approprié.
   - Définissez la [visibilité du projet](../../user/public_access.md) sur **Privé**.

Vous avez correctement dupliqué le modèle de projet `fuzz-testing`. Avant de commencer les tests fuzz, supprimez la relation entre le modèle de projet et la duplication :

1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Paramètres avancés**.
1. Dans la section **Supprimer la relation de bifurcation**, sélectionnez **Supprimer la relation de bifurcation**. Saisissez le nom du projet lorsque vous y êtes invité.

Votre projet est prêt et vous pouvez maintenant créer le test fuzz. Ensuite, vous allez créer les cibles fuzz.

## Créer les cibles fuzz {#create-the-fuzz-targets}

Maintenant que vous disposez d'un projet pour les tests fuzz, vous pouvez créer les cibles fuzz. Une cible fuzz est une fonction ou un programme qui, étant donné une entrée, effectue un appel à l'application testée.

Dans ce tutoriel, les cibles fuzz appellent une fonction du fichier `my-tools.js` en utilisant un buffer aléatoire comme paramètre.

Pour créer les deux fichiers de cibles fuzz :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet `fuzz-testing-demo`.
1. Créez un fichier dans le répertoire racine du projet.
1. Nommez le fichier `fuzz-sayhello.js` et ajoutez le code suivant :

   ```javascript
   let tools = require('./my-tools')

   function fuzz(buf) {
     const text = buf.toString()
     tools.sayHello(text)
   }

   module.exports = {
     fuzz
   }
   ```

   Vous pouvez également copier ce code depuis le fichier de projet `fuzz-testing-demo/fuzzers/fuzz-sayhello.js`.
1. Nommez la **Branche cible** `add-fuzz-test` et rédigez un message de commit descriptif.
   - Ne cochez pas encore la case **Démarrer une nouvelle merge request avec ces modifications**.
1. Sélectionnez **Valider les modifications**.
1. Revenez au répertoire racine du projet.
1. Assurez-vous d'être dans la branche `add-fuzz-test`.
1. Créez le second fichier nommé `fuzz-readme.js` et ajoutez le code suivant :

   ```javascript
   let tools = require('./my-tools')
   function fuzz(buf) {
       const text = buf.toString()
       tools.readmeContent(text)
   }
   module.exports = {
       fuzz
   }
   ```

   Vous pouvez également copier ce code depuis le fichier de projet `fuzz-testing-demo/fuzzers/fuzz-readme.js`.
1. Rédigez un message de commit descriptif.
1. Assurez-vous que la **Branche cible** est `add-fuzz-test`.
1. Sélectionnez **Valider les modifications**.

Vous disposez maintenant de deux cibles fuzz capables d'effectuer des appels à l'application testée. Ensuite, vous allez activer le test fuzz.

## Activer le test fuzz guidé par la couverture {#enable-coverage-guided-fuzz-testing}

Pour activer le test fuzz guidé par la couverture, créez un pipeline CI/CD exécutant la CLI `gitlab-cov-fuzz` afin d'exécuter le test fuzz sur les deux cibles fuzz.

Pour créer le fichier de pipeline :

1. Assurez-vous d'être dans la branche `add-fuzz-test`.
1. Dans le répertoire racine du projet `fuzz-testing-demo`, créez un nouveau fichier.
1. Nommez le fichier `.gitlab-ci.yml` et ajoutez le code suivant :

   ```yaml
   default:
     image: node:18

   stages:
     - fuzz

   include:
     - template: Coverage-Fuzzing.gitlab-ci.yml

   readme_fuzz_target:
     extends: .fuzz_base
     tags: [saas-linux-large-amd64] # Optional
     variables:
       COVFUZZ_ADDITIONAL_ARGS: '--fuzzTime=60'
     script:
       - npm config set @gitlab-org:registry https://gitlab.com/api/v4/packages/npm/ && npm i -g @gitlab-org/jsfuzz
       - ./gitlab-cov-fuzz run --engine jsfuzz -- fuzz-readme.js

   hello_fuzzing_target:
     extends: .fuzz_base
     tags: [saas-linux-large-amd64] # Optional
     variables:
       COVFUZZ_ADDITIONAL_ARGS: '--fuzzTime=60'
     script:
       - npm config set @gitlab-org:registry https://gitlab.com/api/v4/packages/npm/ && npm i -g @gitlab-org/jsfuzz
       - ./gitlab-cov-fuzz run --engine jsfuzz -- fuzz-sayhello.js
   ```

   Cette étape ajoute les éléments suivants à votre pipeline :
   - Une étape `fuzz` utilisant un template.
   - Deux jobs, `readme_fuzz_target` et `hello_fuzzing_target`. Chaque job s'exécute avec le moteur `jsfuzz`, qui signale les exceptions non gérées comme des plantages.

   Vous pouvez également copier ce code depuis le fichier de projet `fuzz-testing-demo/fuzzers/fuzzers.yml`.

1. Rédigez un message de commit descriptif.
1. Assurez-vous que la **Branche cible** est `add-fuzz-test`.
1. Sélectionnez **Valider les modifications**.

Vous avez correctement activé le test fuzz guidé par la couverture. Ensuite, vous allez exécuter le test fuzz à l'aide du pipeline que vous venez de créer.

## Exécuter le test fuzz {#run-the-fuzz-test}

Pour exécuter le test fuzz :

1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**.
1. Sélectionnez **Nouvelle requête de fusion**.
1. Dans la section **Branche source**, sélectionnez la branche `add-fuzz-test`.
1. Dans la section **Branche cible**, assurez-vous que votre espace de nommage et la branche `main` sont sélectionnés.
1. Sélectionnez **Comparer les branches et continuer**.
1. [Créez la merge request](../../user/project/merge_requests/creating_merge_requests.md).

La création de la merge request déclenche un nouveau pipeline, qui exécute le test fuzz. Lorsque le pipeline a terminé son exécution, une alerte de vulnérabilité de sécurité devrait apparaître sur la page de la merge request.

Pour obtenir plus d'informations sur chaque vulnérabilité, sélectionnez les liens **Uncaught-exception** individuels.

Vous avez correctement exécuté le test fuzz et identifié les vulnérabilités à corriger.

## Corriger les vulnérabilités {#fix-the-vulnerabilities}

Le test fuzz a identifié deux vulnérabilités de sécurité. Pour corriger ces vulnérabilités, utilisez la bibliothèque `my-tools.js`.

Pour créer le fichier `my-tools.js` :

1. Assurez-vous d'être dans la branche `add-fuzz-test` du projet.
1. Accédez au répertoire racine de votre projet et ouvrez le fichier `my-tools.js`.
1. Remplacez le contenu de ce fichier par le code suivant :

   ```javascript
   const fs = require('fs')

   function sayHello(name) {
     if(name.includes("z")) {
       //throw new Error("😡 error name: " + name)
       console.log("😡 error name: " + name)
     } else {
       return "😀 hello " + name
     }
   }

   function readmeContent(name) {

     let fileName = name => {
       if(name.includes("w")) {
         return "./README.txt"
       } else {
         return "./README.md"
       }
     }

     //const data = fs.readFileSync(fileName(name), 'utf8')
     try {
       const data = fs.readFileSync(fileName(name), 'utf8')
       return data
     } catch (err) {
       console.error(err.message)
       return ""
     }

   }

   module.exports = {
     sayHello, readmeContent
   }
   ```

   Vous pouvez également copier le code depuis le fichier de projet `fuzz-testing-demo/javascript/my-tools.js`.
1. Sélectionnez **Valider les modifications**. Cela déclenche un autre pipeline pour exécuter un autre test fuzz.
1. Une fois le pipeline terminé, vérifiez la page **Vue d'ensemble** de la merge request. Vous devriez constater que le scan de sécurité n'a détecté aucune nouvelle vulnérabilité potentielle.
1. Fusionnez vos modifications.

Félicitations, vous avez correctement exécuté un test fuzz et corrigé les vulnérabilités de sécurité identifiées !

Pour plus d'informations, consultez [le test fuzz guidé par la couverture](../../user/application_security/coverage_fuzzing/_index.md).

<!--- end_remove -->
