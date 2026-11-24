---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Dépannage du SAST
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les scénarios de dépannage suivants ont été collectés à partir de tickets du support client. Si vous rencontrez un problème non abordé ici, ou si les informations présentes ne résolvent pas votre problème, consultez la page [GitLab Support](https://support.gitlab.com/) pour obtenir de l'aide.

## Journalisation de niveau débogage {#debug-level-logging}

La journalisation de niveau débogage peut être utile lors du dépannage. Pour en savoir plus, reportez-vous à la section [Journalisation de niveau débogage](../troubleshooting_application_security.md#turn-on-debug-level-logging).

## Modifications dans le template CI/CD {#changes-in-the-cicd-template}

Le template CI/CD SAST géré par GitLab contrôle quels jobs d'[analyseur](analyzers.md) s'exécutent et comment ils sont configurés. Lors de l'utilisation du template, vous pourriez rencontrer un échec de job ou une autre erreur de pipeline. Par exemple, vous pourriez :

- Voir un message d'erreur de type `'<your job>' needs 'spotbugs-sast' job, but 'spotbugs-sast' is not in any previous stage` lorsque vous consultez un pipeline affecté.
- Rencontrer un autre type de problème inattendu avec la configuration de votre pipeline CI/CD.

Si vous rencontrez un échec de job ou un statut de pipeline SAST `yaml invalid`, vous pouvez revenir temporairement à une version plus ancienne du template afin que vos pipelines continuent de fonctionner pendant que vous investiguez le problème. Pour utiliser une version plus ancienne du template, modifiez l'instruction `include` existante dans votre fichier YAML CI/CD pour référencer une version spécifique du template, par exemple `v19.2.0-ee` :

```yaml
include:
  remote: 'https://gitlab.com/gitlab-org/gitlab/-/raw/v19.2.0-ee/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml'
```

Si votre instance GitLab dispose d'une connectivité réseau limitée, vous pouvez également télécharger le fichier et l'héberger ailleurs.

Vous ne devez utiliser cette solution que temporairement. Revenez au template standard dès que possible.

## Erreurs dans un job d'analyseur spécifique {#errors-in-a-specific-analyzer-job}

Les [analyseurs](analyzers.md) SAST de GitLab sont publiés sous forme d'images de conteneur. Si vous constatez une nouvelle erreur qui ne semble pas liée au template CI/CD SAST géré par GitLab ou à des modifications de votre propre projet, vous pouvez essayer de [fixer l'analyseur affecté sur une version antérieure spécifique](_index.md#pin-analyzer-image-version). Vous ne devez utiliser cette solution que temporairement. Revenez au template standard dès que possible.

Chaque [projet d'analyseur](analyzers.md) dispose d'un fichier `CHANGELOG.md` répertoriant les modifications apportées dans chaque version disponible.

## Messages du job log {#job-log-messages}

Le job log du SAST peut contenir des messages d'erreur qui aident à identifier la cause racine. Voici quelques-uns des messages d'erreur et des actions recommandées.

### Format d'exécutable {#executable-format}

```plaintext
exec /bin/sh: exec format error` message in job log
```

Les analyseurs SAST de GitLab [ne prennent en charge](_index.md#getting-started) que l'exécution sur l'architecture CPU `amd64`. Ce message indique que le job s'exécute sur une autre architecture, par exemple `arm`.

### Erreur Docker {#docker-error}

```plaintext
Error response from daemon: error processing tar file: docker-tar: relocation error
```

Cette erreur se produit lorsque la version Docker qui exécute le job SAST est `19.03.0`. Envisagez de mettre à jour vers Docker `19.03.1` ou une version supérieure. Les versions antérieures ne sont pas affectées. Pour plus de détails, consultez le [ticket 13830](https://gitlab.com/gitlab-org/gitlab/-/issues/13830#note_211354992) \- « Current SAST container fails ».

### Aucun fichier correspondant {#no-matching-files}

```plaintext
gl-sast-report.json: no matching files
```

Pour plus d'informations, consultez la [section générale de dépannage de la sécurité des applications](../../../ci/jobs/job_artifacts_troubleshooting.md#error-message-no-files-to-upload).

### Configuration uniquement {#configuration-only}

```plaintext
sast is used for configuration only, and its script should not be executed
```

Pour plus d'informations, consultez la [section de dépannage GitLab Secure](../troubleshooting_application_security.md#error-job-is-used-for-configuration-only-and-its-script-should-not-be-executed).

## Erreur : `An error occurred while creating the merge request` {#error-an-error-occurred-while-creating-the-merge-request}

Lors d'une tentative d'activation du SAST sur un projet via l'interface utilisateur, l'opération peut échouer avec l'avertissement suivant :

```plaintext
An error occurred while creating the merge request.
```

Ce problème peut survenir car quelque chose empêche la création de la branche pour la merge request. Lors de la configuration du SAST via l'interface utilisateur, une branche avec un suffixe numérique est créée, par exemple `set-sast-config-1`. Des fonctionnalités telles qu'une [règle de push qui valide les noms de branche](../../project/repository/push_rules.md#validate-branch-names) peuvent bloquer la création de la branche en raison du format de nommage.

Pour résoudre ce problème, modifiez la règle de push afin qu'elle autorise le format de nommage de branche requis par le SAST.

## Les jobs SAST s'exécutent de façon inattendue {#sast-jobs-run-unexpectedly}

Le [template CI SAST](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/SAST.gitlab-ci.yml) utilise le paramètre `rules:exists`. Pour des raisons de performance, un maximum de 10 000 correspondances est effectué pour le motif glob donné. Si le nombre de correspondances dépasse le maximum, le paramètre `rules:exists` retourne `true`. Selon le nombre de fichiers dans votre dépôt, un job SAST peut être déclenché même si le scanner ne prend pas en charge votre projet. Pour plus de détails sur cette limitation, consultez la [documentation de `rules:exists`](../../../ci/yaml/_index.md#rulesexists).

## Erreurs SpotBugs {#spotbugs-errors}

Voici les détails des erreurs SpotBugs les plus courantes et les actions recommandées.

### Erreurs de caractères non mappables UTF-8 {#utf-8-unmappable-character-errors}

Ces erreurs se produisent lorsque l'encodage UTF-8 n'est pas activé dans une compilation SpotBugs et que le code source contient des caractères UTF-8. Pour corriger cette erreur, activez UTF-8 pour l'outil de compilation de votre projet.

Pour les compilations Gradle, ajoutez ce qui suit à votre fichier `build.gradle` :

```groovy
compileJava.options.encoding = 'UTF-8'
tasks.withType(JavaCompile) {
    options.encoding = 'UTF-8'
}
```

Pour les compilations Maven, ajoutez ce qui suit à votre fichier `pom.xml` :

```xml
<properties>
  <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
</properties>
```

### Le projet n'a pas pu être compilé {#project-couldnt-be-built}

Si votre job `spotbugs-sast` échoue à l'étape de compilation avec le message « Project couldn't be built », c'est très probablement parce que :

- Votre projet demande à SpotBugs de compiler avec un outil qui ne fait pas partie de ses outils par défaut. Pour obtenir la liste des outils par défaut de SpotBugs, consultez [les dépendances asdf de SpotBugs](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs/-/blob/master/config/.gl-tool-versions).
- Votre compilation nécessite des configurations personnalisées ou des dépendances supplémentaires que le processus de compilation automatique de l'analyseur ne peut pas prendre en charge.

L'analyseur basé sur SpotBugs est uniquement utilisé pour analyser le code Groovy, mais il peut se déclencher dans d'autres cas, par exemple [lorsque tous les jobs SAST s'exécutent de façon inattendue](#sast-jobs-run-unexpectedly).

La solution dépend de si vous avez besoin d'analyser du code Groovy :

- Si vous n'avez pas de code Groovy ou n'avez pas besoin de l'analyser, vous devriez [désactiver l'analyseur SpotBugs](analyzers.md#disable-specific-default-analyzers).
- Si vous avez besoin d'analyser du code Groovy, vous devriez utiliser la [pré-compilation](_index.md#using-pre-compilation-with-spotbugs-analyzer). La pré-compilation évite ces échecs en analysant un artefact que vous avez déjà compilé dans votre pipeline, plutôt que d'essayer de le compiler dans le job `spotbugs-sast`.

### Erreur de mémoire insuffisante Java {#java-out-of-memory-error}

Lors de l'exécution d'un job `spotbugs-sast`, vous pourriez obtenir une erreur indiquant `java.lang.OutOfMemoryError`. Ce problème se produit lorsque Java manque de mémoire pendant l'analyse.

Pour tenter de résoudre ce problème, vous pouvez :

- Choisir un [niveau d'effort](_index.md#security-scanner-configuration) inférieur.
- Définir la variable CI/CD `JAVA_OPTS` pour remplacer la valeur par défaut `-XX:MaxRAMPercentage=80` (par exemple : `-XX:MaxRAMPercentage=90`).
- [Associer un runner plus puissant](../../../ci/runners/hosted_runners/linux.md#machine-types-available-for-linux-x86-64) à votre job `spotbugs-sast`.

#### Sujets connexes {#related-topics}

- [Révision de l'optimisation de la mémoire dans les mises à jour des conteneurs OpenJDK](https://developers.redhat.com/articles/2023/03/07/overhauling-memory-tuning-openjdk-containers-updates)
- [Configuration et optimisation d'OpenJDK](https://wiki.openjdk.org/display/zgc/Main#Main-Configuration&Tuning)
- [Optimisation du ramasse-miettes Garbage First](https://www.oracle.com/technical-resources/articles/java/g1gc.html)

### Exception lors de l'analyse {#exception-analyzing}

Si votre job log contient un message de la forme « Exception analyzing ... using detector ... » suivi d'une trace de pile Java, il ne s'agit pas d'un échec du pipeline SAST. SpotBugs a déterminé que l'exception est [récupérable](https://github.com/spotbugs/spotbugs/blob/5ebd4439f6f8f2c11246b79f58c44324718d39d8/spotbugs/src/main/java/edu/umd/cs/findbugs/FindBugs2.java#L1200), l'a journalisée et a repris l'analyse.

La première partie « ... » du message correspond à la classe en cours d'analyse ; si elle ne fait pas partie de votre projet, vous pouvez probablement ignorer le message et la trace de pile qui suit.

En revanche, si la classe en cours d'analyse fait partie de votre projet, envisagez de créer un ticket auprès du projet SpotBugs sur [GitHub](https://github.com/spotbugs/spotbugs/issues).

## Erreur d'encodage Flawfinder {#flawfinder-encoding-error}

Cela se produit lorsque Flawfinder rencontre un caractère UTF-8 invalide. Pour corriger cela, appliquez [leur conseil documenté](https://github.com/david-a-wheeler/flawfinder#character-encoding-errors) à l'ensemble de votre dépôt, ou uniquement par job en utilisant la fonctionnalité [`before_script`](../../../ci/yaml/_index.md#before_script).

Vous pouvez configurer la section `before_script` dans chaque fichier `.gitlab-ci.yml`, ou utiliser une [politique d'exécution de pipeline](../policies/pipeline_execution_policies.md) pour installer l'encodeur et exécuter la commande de conversion. Par exemple, vous pouvez ajouter une section `before_script` au job `flawfinder-sast` généré depuis le template du scanner de sécurité pour convertir tous les fichiers avec une extension `.cpp`.

### Exemple de YAML de politique d'exécution de pipeline {#example-pipeline-execution-policy-yaml}

```yaml
---
pipeline_execution_policy:
- name: SAST
  description: 'Run SAST on C++ application'
  enabled: true
  pipeline_config_strategy: inject_ci
  content:
    include:
    - project: my-group/compliance-project
      file: flawfinder.yml
      ref: main
```

`flawfinder.yml` :

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

flawfinder-sast:
  before_script:
    - pip install cvt2utf
    - cvt2utf convert "$PWD" -i cpp
```

## Lenteur de Semgrep, résultats inattendus ou autres erreurs {#semgrep-slowness-unexpected-results-or-other-errors}

Si Semgrep est lent, signale trop de faux positifs ou de faux négatifs, plante, échoue ou présente tout autre dysfonctionnement, consultez la documentation Semgrep pour le [dépannage du SAST GitLab](https://semgrep.dev/docs/troubleshooting/semgrep-app#troubleshooting-gitlab-sast).
