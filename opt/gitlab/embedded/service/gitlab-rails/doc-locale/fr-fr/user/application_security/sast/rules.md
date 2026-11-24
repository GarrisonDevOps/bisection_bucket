---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Règles SAST
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Le test statique de sécurité des applications (SAST) GitLab utilise un ensemble d'[analyseurs](analyzers.md) pour analyser le code à la recherche de vulnérabilités potentielles. Il choisit automatiquement les analyseurs à exécuter en fonction des langages de programmation détectés dans le dépôt.

Chaque analyseur traite le code, puis utilise des règles pour détecter d'éventuelles failles dans le code source. Les règles de l'analyseur déterminent les types de failles qu'il signale.

## Portée des règles {#scope-of-rules}

SAST se concentre sur les failles et les vulnérabilités de sécurité. Son objectif n'est pas de détecter les bugs généraux ni d'évaluer la qualité globale du code ou sa maintenabilité.

GitLab gère l'ensemble de règles de détection en mettant l'accent sur l'identification des failles et des vulnérabilités de sécurité exploitables. L'ensemble de règles est conçu pour offrir une couverture étendue contre les vulnérabilités les plus impactantes, tout en minimisant les faux positifs (vulnérabilités signalées alors qu'aucune vulnérabilité n'existe).

SAST est conçu pour être utilisé dans sa configuration par défaut, mais vous pouvez [configurer les règles de détection](#configure-rules-in-your-projects) si nécessaire.

## Source des règles {#source-of-rules}

Les règles de détection des vulnérabilités utilisées par SAST dépendent de l'analyseur employé, que ce soit GitLab Advanced SAST ou l'analyseur basé sur Semgrep.

### GitLab Advanced SAST {#gitlab-advanced-sast}

{{< details >}}

- Édition : GitLab Ultimate

{{< /details >}}

GitLab crée, maintient et prend en charge les règles pour [GitLab Advanced SAST](gitlab_advanced_sast.md). Ses règles sont spécialement conçues pour exploiter les capacités d'analyse inter-fichiers et inter-fonctions du moteur d'analyse de GitLab Advanced SAST. L'ensemble de règles de GitLab Advanced SAST n'est pas open source et n'est pas le même ensemble de règles que celui de tout autre analyseur.

Pour en savoir plus sur les types de vulnérabilités détectées par GitLab Advanced SAST, consultez [Critères de détection des vulnérabilités](gitlab_advanced_sast.md#vulnerability-detection-criteria).

Pour obtenir la liste complète des règles utilisées par GitLab Advanced SAST, consultez [Règles de GitLab Advanced SAST](glas_rules_docs/_index.md).

### Analyseur basé sur Semgrep {#semgrep-based-analyzer}

GitLab crée, maintient et prend en charge les règles utilisées dans l'analyseur GitLab SAST basé sur Semgrep. Cet analyseur analyse [de nombreux langages](_index.md#supported-languages-and-frameworks) dans un seul job de pipeline CI/CD. Il combine :

- Le moteur open source Semgrep.
- Un ensemble de règles de détection géré par GitLab, administré dans [le projet open source géré par GitLab `sast-rules`](https://gitlab.com/gitlab-org/security-products/sast-rules).
- La technologie propriétaire de GitLab pour le [suivi des vulnérabilités](_index.md#advanced-vulnerability-tracking).

### Autres analyseurs {#other-analyzers}

GitLab SAST utilise d'autres analyseurs pour analyser les [langages pris en charge](_index.md#supported-languages-and-frameworks) restants. Les règles pour ces analyses sont définies dans les projets en amont de chaque scanner.

## Modalités de publication des mises à jour de règles {#how-rule-updates-are-released}

GitLab met à jour les règles régulièrement en fonction des retours des clients et des recherches internes. Les règles sont publiées dans le cadre de l'image de conteneur de chaque analyseur. Vous recevez automatiquement les analyseurs et les règles mis à jour, sauf si vous [épinglez manuellement les analyseurs à une version spécifique](_index.md#pin-analyzer-image-version).

Les analyseurs et leurs règles sont mis à jour [au moins mensuellement](../detect/vulnerability_scanner_maintenance.md) si des mises à jour pertinentes sont disponibles.

### Politiques de mise à jour des règles {#rule-update-policies}

Les mises à jour des règles SAST ne constituent pas des [changements majeurs](../../../update/terminology.md#breaking-change). Cela signifie que des règles peuvent être ajoutées, supprimées ou mises à jour sans préavis.

Toutefois, afin de rendre les modifications de règles plus pratiques et compréhensibles, GitLab :

- Documente les [modifications de règles](#important-rule-changes) planifiées ou effectuées.
- [Résout automatiquement](_index.md#automatic-vulnerability-resolution) les résultats issus des règles après leur suppression pour les analyseurs basés sur Semgrep.
- Vous permet de [modifier en masse le statut des vulnérabilités dont l'activité est « plus détectée »](../vulnerability_report/_index.md#change-status-of-vulnerabilities).
- Évalue les modifications de règles proposées en fonction de leur impact sur les enregistrements de vulnérabilités existants.

## Configurer les règles dans vos projets {#configure-rules-in-your-projects}

Vous devez utiliser les règles SAST par défaut, sauf si vous avez une raison spécifique d'effectuer une modification. L'ensemble de règles par défaut est conçu pour être adapté à la plupart des projets.

Toutefois, vous pouvez [personnaliser les règles utilisées](#apply-local-rule-preferences) ou [contrôler le déploiement des modifications de règles](#coordinate-rule-rollouts) si nécessaire.

### Appliquer des préférences de règles locales {#apply-local-rule-preferences}

Vous pouvez souhaiter personnaliser les règles utilisées dans les analyses SAST pour les raisons suivantes :

- Votre organisation a défini des priorités pour des classes de vulnérabilités spécifiques, par exemple en choisissant de traiter le Cross-Site Scripting (XSS) ou l'injection SQL avant d'autres classes de vulnérabilités.
- Vous pensez qu'une règle spécifique constitue un faux positif ou n'est pas pertinente dans le contexte de votre base de code.

Pour modifier les règles utilisées pour analyser vos projets, ajuster leur gravité ou appliquer d'autres préférences, consultez [Personnaliser les ensembles de règles](customize_rulesets.md). Si votre personnalisation peut bénéficier à d'autres utilisateurs, envisagez de [signaler un problème à GitLab](#report-a-problem-with-a-gitlab-sast-rule).

### Coordonner le déploiement des règles {#coordinate-rule-rollouts}

Pour contrôler le déploiement des modifications de règles, vous pouvez [épingler les analyseurs SAST à une version spécifique](_index.md#pin-analyzer-image-version).

Si vous souhaitez apporter ces modifications simultanément à plusieurs projets, envisagez de définir les variables dans :

- [Variables CI/CD au niveau du groupe](../../../ci/variables/_index.md#for-a-group).
- Variables CI/CD personnalisées dans une [politique d'exécution de scan](../policies/scan_execution_policies.md).

## Signaler un problème avec une règle SAST GitLab {#report-a-problem-with-a-gitlab-sast-rule}
<!-- This title is intended to match common search queries users might make. -->

GitLab accueille favorablement les contributions aux ensembles de règles utilisés dans SAST. Les contributions peuvent concerner :

- Les faux positifs, où la vulnérabilité potentielle signalée est incorrecte.
- Les faux négatifs, où SAST n'a pas signalé une vulnérabilité potentielle qui existe réellement.
- Le nom, la cote de gravité, la description, les conseils ou tout autre contenu explicatif associé à une règle.

Si vous pensez qu'une règle de détection pourrait être améliorée pour tous les utilisateurs, envisagez :

- De soumettre une merge request dans le [dépôt `sast-rules`](https://gitlab.com/gitlab-org/security-products/sast-rules). Consultez les [instructions de contribution](https://gitlab.com/gitlab-org/security-products/sast-rules#contributing) pour plus de détails.
- De créer un ticket dans le [système de suivi des tickets `gitlab-org/gitlab`](https://gitlab.com/gitlab-org/gitlab/-/issues/).
  - Publiez un commentaire indiquant `@gitlab-bot label ~"group::static analysis" ~"Category:SAST"` pour que votre ticket soit acheminé vers le workflow de triage approprié.

## Modifications importantes des règles {#important-rule-changes}

GitLab met à jour les règles SAST [régulièrement](#how-rule-updates-are-released). Cette section met en évidence les modifications les plus importantes. De plus amples détails sont disponibles dans les annonces de release et dans les liens CHANGELOG fournis.

### Modifications des règles dans l'analyseur basé sur Semgrep {#rule-changes-in-the-semgrep-based-analyzer}

Les principales modifications apportées à l'ensemble de règles géré par GitLab pour l'analyse basée sur Semgrep sont les suivantes :

- À partir de GitLab 16.3, les équipes GitLab Static Analysis et Vulnerability Research travaillent à la suppression des règles qui tendent à produire trop de faux positifs ou un nombre insuffisant de vrais positifs exploitables. Les résultats existants issus de ces règles supprimées sont [automatiquement résolus](_index.md#automatic-vulnerability-resolution) ; ils n'apparaissent plus dans le [Tableau de bord de sécurité](../security_dashboard/_index.md#project-security-dashboard) ni dans la vue par défaut du [rapport de vulnérabilités](../vulnerability_report/_index.md). Ce travail est suivi dans l'[epic 10907](https://gitlab.com/groups/gitlab-org/-/epics/10907).
- Dans GitLab 16.0 à 16.2, l'équipe GitLab Vulnerability Research a mis à jour les conseils inclus dans chaque résultat.
- Dans GitLab 15.10, la règle `detect-object-injection` a été [supprimée par défaut](https://gitlab.com/gitlab-org/gitlab/-/issues/373920) et ses résultats ont été [automatiquement résolus](_index.md#automatic-vulnerability-resolution).

Pour plus de détails, consultez le [CHANGELOG de `sast-rules`](https://gitlab.com/gitlab-org/security-products/sast-rules/-/blob/main/CHANGELOG.md).

### Modifications des règles dans d'autres analyseurs {#rule-changes-in-other-analyzers}

Consultez le fichier CHANGELOG de chaque [analyseur](analyzers.md) pour obtenir des détails sur les modifications, notamment les règles nouvelles ou mises à jour, incluses dans chaque version.
