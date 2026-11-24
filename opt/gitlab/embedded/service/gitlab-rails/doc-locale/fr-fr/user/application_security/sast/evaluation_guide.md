---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Apprenez à évaluer GitLab SAST en sélectionnant une base de code de test, en configurant les analyses, en interprétant les résultats et en comparant les fonctionnalités avec d'autres outils de sécurité."
title: Évaluer GitLab SAST
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez choisir d'évaluer GitLab SAST avant de l'utiliser dans votre organisation. Tenez compte des recommandations suivantes lors de la planification et de la conduite de votre évaluation.

## Concepts importants {#important-concepts}

GitLab SAST est conçu pour aider les équipes à améliorer collectivement la sécurité du code qu'elles écrivent. Les étapes que vous suivez pour analyser votre code et consulter les résultats sont centrées sur le dépôt de code source analysé.

### Processus d'analyse {#scanning-process}

GitLab SAST sélectionne automatiquement la technologie d'analyse appropriée en fonction des langages de programmation présents dans votre projet. Pour tous les langages à l'exception de Groovy, GitLab SAST analyse votre code source directement, sans nécessiter d'étape de compilation ou de build. Cela facilite l'activation de l'analyse sur un grand nombre de projets. Pour plus de détails, consultez [Langages et frameworks pris en charge](_index.md#supported-languages-and-frameworks).

### Quand les vulnérabilités sont signalées {#when-vulnerabilities-are-reported}

Les [analyseurs](analyzers.md) GitLab SAST et leurs [règles](rules.md) sont conçus pour minimiser le bruit pour les équipes de développement et de sécurité.

Pour plus de détails sur le moment où l'analyseur GitLab Advanced SAST signale des vulnérabilités, consultez [Critères de détection des vulnérabilités](gitlab_advanced_sast.md#vulnerability-detection-criteria).

### Autres fonctionnalités de la plateforme {#other-platform-features}

SAST est intégré aux autres fonctionnalités de sécurité et de conformité de GitLab Ultimate. Si vous comparez GitLab SAST à un autre produit, vous constaterez peut-être que certaines de ses fonctionnalités sont incluses dans un domaine de fonctionnalités GitLab associé plutôt que dans SAST :

- [L'analyse IaC](../iac_scanning/_index.md) analyse vos définitions d'Infrastructure as Code (IaC) à la recherche de problèmes de sécurité.
- [La détection des secrets](../secret_detection/_index.md) identifie les secrets exposés dans votre code.
- [Les politiques de sécurité](../policies/_index.md) vous permettent de forcer l'exécution des analyses ou d'exiger que les vulnérabilités soient corrigées.
- [La gestion et le reporting des vulnérabilités](../vulnerability_report/_index.md) gère les vulnérabilités présentes dans la base de code et s'intègre aux outils de suivi de tickets.
- GitLab Duo [explication des vulnérabilités](../analyze/duo.md) et [résolution des vulnérabilités](../remediate/duo.md) vous aident à remédier rapidement aux vulnérabilités grâce à l'IA.

## Choisir une base de code de test {#choose-a-test-codebase}

Lors du choix d'une base de code pour tester SAST, vous devez :

- Effectuer les tests dans un dépôt où vous pouvez modifier la configuration CI/CD en toute sécurité sans perturber les activités de développement normales. Les analyses SAST s'exécutent dans votre pipeline CI/CD ; vous devez donc apporter une petite modification à la configuration CI/CD pour [activer SAST](_index.md#configuration).
  - Vous pouvez dupliquer ou copier un dépôt existant à des fins de test. Ainsi, vous pouvez configurer votre environnement de test sans risquer d'interrompre le développement normal.
- Utiliser une base de code correspondant à la stack technologique habituelle de votre organisation.
- Utiliser un langage [pris en charge par GitLab Advanced SAST](gitlab_advanced_sast.md#supported-languages). GitLab Advanced SAST produit des résultats plus précis que les autres [analyseurs](analyzers.md).

Votre projet de test doit disposer de GitLab Ultimate. Seul GitLab Ultimate inclut des [fonctionnalités](_index.md#features) telles que :

- Analyse propriétaire inter-fichiers et inter-fonctions avec GitLab Advanced SAST.
- L'onglet **Rapports** de la merge request, le rapport de sécurité du pipeline et le rapport de vulnérabilités de la branche par défaut, qui rendent les résultats d'analyse visibles et exploitables.

### Benchmarks et exemples de projets {#benchmarks-and-example-projects}

Si vous choisissez d'utiliser un benchmark ou une application intentionnellement vulnérable pour les tests, gardez à l'esprit que ces applications :

- Se concentrent sur des types de vulnérabilités spécifiques. La priorité du benchmark peut différer des types de vulnérabilités que votre organisation privilégie pour la découverte et la remédiation.
- Utilisent des technologies spécifiques de manière particulière, qui peuvent différer de la façon dont votre organisation développe ses logiciels.
- Présentent les résultats d'une manière qui peut implicitement mettre en avant certains critères plutôt que d'autres. Par exemple, vous pouvez privilégier la précision (moins de faux positifs), tandis que le benchmark n'évalue que sur la base du rappel (moins de faux négatifs).

[L'epic 15296](https://gitlab.com/groups/gitlab-org/-/epics/15296) suit les travaux visant à recommander des projets spécifiques pour les tests.

### Code de test généré par IA {#ai-generated-test-code}

Vous ne devez pas utiliser des outils d'IA pour créer du code vulnérable à des fins de test SAST. Les modèles d'IA renvoient souvent du code qui n'est pas réellement exploitable.

Par exemple :

- Les outils d'IA écrivent souvent de petites fonctions qui prennent un paramètre et l'utilisent dans un contexte sensible (appelé « sink »), sans recevoir réellement de saisie utilisateur. Il peut s'agir d'une conception sûre si la fonction est uniquement appelée avec des valeurs contrôlées par le programme, comme des constantes. Le code n'est pas vulnérable, sauf si la saisie utilisateur est autorisée à transiter vers ces sinks sans être préalablement assainie ou validée.
- Les outils d'IA peuvent commenter une partie de la vulnérabilité pour éviter que vous n'exécutiez accidentellement le code.

Signaler des vulnérabilités dans ces exemples non réalistes entraînerait des faux positifs dans du code réel. GitLab SAST n'est pas conçu pour signaler des vulnérabilités dans ces cas.

## Effectuer le test {#conduct-the-test}

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Après avoir choisi une base de code à tester, vous êtes prêt à effectuer le test. Vous pouvez suivre les étapes suivantes :

1. [Activez SAST](_index.md#configuration) en créant une merge request (MR) qui ajoute SAST à la configuration CI/CD.
   - Veillez à définir la variable CI/CD pour [activer GitLab Advanced SAST](gitlab_advanced_sast.md#turn-on-gitlab-advanced-sast) afin d'obtenir des résultats plus précis.
1. Fusionnez la merge request dans la branche par défaut du dépôt.
1. Ouvrez le [rapport de vulnérabilités](../vulnerability_report/_index.md) pour consulter les vulnérabilités détectées sur la branche par défaut.
   - Si vous utilisez GitLab Advanced SAST, vous pouvez utiliser le [filtre Scanner](../vulnerability_report/_index.md#scanner-filter) pour afficher uniquement les résultats de cet analyseur.
1. Passez en revue les résultats de vulnérabilités.
   - Consultez la [vue du flux de code](../vulnerabilities/_index.md#vulnerability-code-flow) pour les vulnérabilités GitLab Advanced SAST qui impliquent des saisies utilisateur corrompues, comme les injections SQL ou les traversées de chemin.
   - Si vous disposez de GitLab Duo Enterprise, [expliquez](../analyze/duo.md) ou [résolvez](../remediate/duo.md) une vulnérabilité.
1. Pour voir comment l'analyse fonctionne au fur et à mesure du développement du nouveau code, créez une nouvelle merge request qui modifie le code applicatif et introduit une nouvelle vulnérabilité ou faiblesse.
