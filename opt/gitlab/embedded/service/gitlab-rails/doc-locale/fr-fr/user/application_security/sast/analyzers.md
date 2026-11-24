---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Analyseurs SAST
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Déplacé](https://gitlab.com/groups/gitlab-org/-/epics/2098) de GitLab Ultimate vers GitLab Free dans la version 13.3.

{{< /history >}}

Le test statique de sécurité des applications (SAST) utilise des analyseurs pour détecter les vulnérabilités dans le code source. Chaque analyseur est une surcouche autour d'un [scanner](../terminology/_index.md#scanner), un outil tiers d'analyse de code.

Les analyseurs sont publiés sous forme d'images Docker que le SAST utilise pour lancer des conteneurs dédiés à chaque analyse. Nous recommandons un minimum de 4 Go de RAM pour garantir des performances constantes des analyseurs.

Les images par défaut du SAST sont maintenues par GitLab, mais vous pouvez également intégrer votre propre image personnalisée.

Pour chaque scanner, un analyseur :

- Expose sa logique de détection.
- Gère son exécution.
- Convertit sa sortie vers un [format standard](../terminology/_index.md#secure-report-format).

## Analyseurs officiels {#official-analyzers}

Le SAST prend en charge les analyseurs officiels suivants :

- [`gitlab-advanced-sast`](gitlab_advanced_sast.md), fournissant une analyse de contamination inter-fichiers et inter-fonctions ainsi qu'une précision de détection améliorée. GitLab Ultimate uniquement.
- [`gitlab-advanced-sast-ext`](advanced_sast_swift_objc.md), fournissant une analyse de contamination inter-fichiers et inter-fonctions pour Swift et Objective-C. GitLab Ultimate uniquement. Version bêta.
- [`kubesec`](https://gitlab.com/gitlab-org/security-products/analyzers/kubesec), basé sur Kubesec. Désactivé par défaut ; voir [Activation de l'analyseur KubeSec](_index.md#enabling-kubesec-analyzer).
- [`pmd-apex`](https://gitlab.com/gitlab-org/security-products/analyzers/pmd-apex), basé sur PMD avec des règles pour le langage Apex.
- [`semgrep`](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep), basé sur le moteur Semgrep OSS [avec des règles gérées par GitLab](rules.md#semgrep-based-analyzer).
- [`sobelow`](https://gitlab.com/gitlab-org/security-products/analyzers/sobelow), basé sur Sobelow.
<!-- vale gitlab_base.OxfordComma = NO -->
- [`spotbugs`](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs), basé sur SpotBugs avec le plugin Find Sec Bugs (Ant, Gradle et wrapper, Grails, Maven et wrapper, SBT).
<!-- vale gitlab_base.OxfordComma = YES -->

### Versions prises en charge {#supported-versions}

Les analyseurs officiels sont publiés sous forme d'images de conteneur, indépendamment de la plateforme GitLab. Chaque version d'analyseur est compatible avec un ensemble limité de versions de GitLab.

Lorsqu'une version d'analyseur ne sera plus prise en charge dans une future version de GitLab, ce changement est annoncé à l'avance. Par exemple, consultez l'[annonce pour GitLab 17.0](../../../update/deprecations.md#secure-analyzers-major-version-update).

La version majeure prise en charge pour chaque analyseur officiel est reflétée dans sa définition de job dans le [modèle CI/CD SAST](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml). Pour consulter la version de l'analyseur prise en charge dans une version précédente de GitLab, sélectionnez une version historique du fichier de modèle SAST, telle que [v16.11.0-ee](https://gitlab.com/gitlab-org/gitlab/-/blob/v16.11.0-ee/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml?ref_type=tags) pour GitLab 16.11.0.

## Analyseurs ayant atteint la fin de support {#analyzers-that-have-reached-end-of-support}

Les analyseurs GitLab suivants ont atteint le statut [Fin de support](../../../update/terminology.md#end-of-support) et ne reçoivent plus de mises à jour. Ils ont été remplacés par l'analyseur basé sur Semgrep [avec des règles gérées par GitLab](rules.md#semgrep-based-analyzer).

Après la mise à niveau vers GitLab 17.3.1 ou une version ultérieure, une migration de données unique [résout automatiquement](_index.md#automatic-vulnerability-resolution) les résultats des analyseurs ayant atteint la fin de support. Cela inclut tous les analyseurs listés ci-dessous, à l'exception de SpotBugs, car SpotBugs analyse encore le code Groovy. La migration résout uniquement les vulnérabilités que vous n'avez pas confirmées ou ignorées, et n'affecte pas les vulnérabilités qui ont été [automatiquement traduites vers l'analyse basée sur Semgrep](#transition-to-semgrep-based-scanning). Pour plus de détails, consultez le [ticket 444926](https://gitlab.com/gitlab-org/gitlab/-/issues/444926).

| Analyseur                                                                                                   | Langages analysés                                                                      | Version GitLab de fin de support                                                                 |
|------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| [Bandit](https://gitlab.com/gitlab-org/security-products/analyzers/bandit)                                 | Python                                                                                 | [15.4](../../../update/deprecations.md#sast-analyzer-consolidation-and-cicd-template-changes) |
| [Brakeman](https://gitlab.com/gitlab-org/security-products/analyzers/brakeman)                             | Ruby, y compris Ruby on Rails                                                          | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |
| [ESLint](https://gitlab.com/gitlab-org/security-products/analyzers/eslint) avec les plugins React et Security | JavaScript et TypeScript, y compris React                                             | [15.4](../../../update/deprecations.md#sast-analyzer-consolidation-and-cicd-template-changes) |
| [Flawfinder](https://gitlab.com/gitlab-org/security-products/analyzers/flawfinder)                         | C, C++                                                                                 | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |
| [gosec](https://gitlab.com/gitlab-org/security-products/analyzers/gosec)                                   | Go                                                                                     | [15.4](../../../update/deprecations.md#sast-analyzer-consolidation-and-cicd-template-changes) |
| [MobSF](https://gitlab.com/gitlab-org/security-products/analyzers/mobsf)                                   | Java et Kotlin, pour les applications Android uniquement ; Objective-C, pour les applications iOS uniquement | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |
| [NodeJsScan](https://gitlab.com/gitlab-org/security-products/analyzers/nodejs-scan)                        | JavaScript (Node.js uniquement)                                                              | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |
| [phpcs-security-audit](https://gitlab.com/gitlab-org/security-products/analyzers/phpcs-security-audit)     | PHP                                                                                    | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |
| [Security Code Scan](https://gitlab.com/gitlab-org/security-products/analyzers/security-code-scan)         | .NET (y compris C#, Visual Basic)                                                      | [16.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-160)         |
| [SpotBugs](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs)                             | Java uniquement[^remains-supported-analyzer]                                                                  | [15.4](../../../update/deprecations.md#sast-analyzer-consolidation-and-cicd-template-changes) |
| [SpotBugs](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs)                             | Kotlin et Scala uniquement[^remains-supported-analyzer]                                                      | [17.0](../../../update/deprecations.md#sast-analyzer-coverage-changing-in-gitlab-170)         |

[^remains-supported-analyzer]: SpotBugs reste un [analyseur pris en charge](_index.md#supported-languages-and-frameworks) pour Groovy. Il ne s'active que lorsque du code Groovy est détecté.

## Fonctionnalités des analyseurs SAST {#sast-analyzer-features}

Pour qu'un analyseur soit considéré comme généralement disponible, il doit au minimum prendre en charge les fonctionnalités suivantes :

- [Configuration personnalisable](_index.md#available-cicd-variables)
- [Ensembles de règles personnalisables](customize_rulesets.md)
- [Analyser des projets](_index.md#supported-languages-and-frameworks)
- Prise en charge multi-projets
- [Prise en charge hors ligne](_index.md#running-sast-in-an-offline-environment)
- [Sortie des résultats au format de rapport JSON](_index.md#download-a-sast-report)
- [Prise en charge de SELinux](_index.md#running-sast-in-selinux)

## Post-analyseurs {#post-analyzers}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les post-analyseurs enrichissent la sortie du rapport produit par un analyseur. Un post-analyseur ne modifie pas directement le contenu du rapport. Il améliore plutôt les résultats avec des propriétés supplémentaires, notamment :

- CWE.
- Champs de suivi de localisation.

## Transition vers l'analyse basée sur Semgrep {#transition-to-semgrep-based-scanning}

En plus de l'[analyseur GitLab Advanced SAST](gitlab_advanced_sast.md), GitLab fournit également un [analyseur basé sur Semgrep](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep) qui couvre [plusieurs langages](_index.md#supported-languages-and-frameworks). GitLab maintient l'analyseur et rédige des [règles de détection](rules.md) pour celui-ci. Ces règles remplacent les analyseurs spécifiques à chaque langage qui étaient utilisés dans les releases précédentes.

### Traduction des vulnérabilités {#vulnerability-translation}

Le système de gestion des vulnérabilités déplace automatiquement les vulnérabilités de l'ancien analyseur vers un nouveau résultat basé sur Semgrep, lorsque cela est possible. Pour la traduction vers l'analyseur GitLab Advanced SAST, référez-vous à la [documentation de GitLab Advanced SAST](gitlab_advanced_sast.md).

Lorsque cela se produit, le système combine les vulnérabilités de chaque analyseur en un seul enregistrement.

Cependant, les vulnérabilités peuvent ne pas correspondre si :

- La nouvelle règle basée sur Semgrep détecte la vulnérabilité à un emplacement différent, ou d'une manière différente, par rapport à l'ancien analyseur.
- Vous avez précédemment [désactivé des analyseurs SAST](#disable-specific-default-analyzers).

Cela peut interférer avec la traduction automatique en empêchant l'enregistrement des identifiants nécessaires pour chaque vulnérabilité.

Si une vulnérabilité ne correspond pas :

- La vulnérabilité d'origine est marquée comme « plus détectée » dans le rapport de vulnérabilités.
- Une nouvelle vulnérabilité est alors créée sur la base du résultat Semgrep.

## Personnaliser les analyseurs {#customize-analyzers}

Utilisez des [variables CI/CD](_index.md#available-cicd-variables) dans votre fichier `.gitlab-ci.yml` pour personnaliser le comportement de vos analyseurs.

### Utiliser un miroir Docker personnalisé {#use-a-custom-docker-mirror}

Vous pouvez utiliser un registre Docker personnalisé, à la place du registre GitLab, pour héberger les images des analyseurs.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.
- Le registre Docker personnalisé doit fournir des images pour tous les analyseurs officiels.

> [!note]
> Cette variable affecte tous les analyseurs Secure, pas seulement les analyseurs pour le SAST.

Pour que GitLab télécharge les images des analyseurs depuis un registre Docker personnalisé, définissez le préfixe avec la variable CI/CD `SECURE_ANALYZERS_PREFIX`.

Par exemple, l'instruction suivante demande au SAST de récupérer `my-docker-registry/gitlab-images/semgrep` au lieu de `registry.gitlab.com/security-products/semgrep` :

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  SECURE_ANALYZERS_PREFIX: my-docker-registry/gitlab-images
```

### Désactiver tous les analyseurs par défaut {#disable-all-default-analyzers}

Vous pouvez désactiver tous les analyseurs SAST par défaut, en laissant uniquement les [analyseurs personnalisés](#custom-analyzers) activés.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour désactiver tous les analyseurs par défaut, définissez la variable CI/CD `SAST_DISABLED` sur `"true"` dans votre fichier `.gitlab-ci.yml`.

Exemple :

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  SAST_DISABLED: "true"
```

### Désactiver des analyseurs par défaut spécifiques {#disable-specific-default-analyzers}

Les analyseurs sont exécutés automatiquement en fonction des langages de code source détectés. Cependant, vous pouvez désactiver certains analyseurs.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour désactiver certains analyseurs, définissez la variable CI/CD `SAST_EXCLUDED_ANALYZERS` sur une chaîne délimitée par des virgules listant les analyseurs que vous souhaitez empêcher de s'exécuter.

Par exemple, pour désactiver l'analyseur `spotbugs` :

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  SAST_EXCLUDED_ANALYZERS: "spotbugs"
```

### Analyseurs personnalisés {#custom-analyzers}

Vous pouvez fournir vos propres analyseurs en définissant des jobs dans votre configuration CI/CD. Pour assurer la cohérence avec les analyseurs par défaut, vous devez ajouter le suffixe `-sast` à vos jobs SAST personnalisés.

#### Exemple d'analyseur personnalisé {#example-custom-analyzer}

Cet exemple montre comment ajouter un job d'analyse basé sur l'image Docker `my-docker-registry/analyzers/csharp`. Il exécute le script `/analyzer run` et génère un rapport SAST `gl-sast-report.json`.

Définissez les éléments suivants dans votre fichier `.gitlab-ci.yml` :

```yaml
csharp-sast:
  image:
    name: "my-docker-registry/analyzers/csharp"
  script:
    - /analyzer run
  artifacts:
    reports:
      sast: gl-sast-report.json
```
