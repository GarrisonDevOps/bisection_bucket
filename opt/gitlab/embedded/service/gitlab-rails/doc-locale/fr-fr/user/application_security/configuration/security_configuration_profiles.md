---
stage: Security Governance
group: Security Controls
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Gestion des profils de configuration de sécurité
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/19802) dans GitLab 18.9 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `security_scan_profiles_feature`. Activés par défaut.
- Profil de détection des secrets [ajouté](https://gitlab.com/groups/gitlab-org/-/epics/19903) dans GitLab 18.10.
- Profil SAST [ajouté](https://gitlab.com/groups/gitlab-org/-/epics/19951) dans GitLab 18.11.
- Profil d'analyse des dépendances [introduit](https://gitlab.com/groups/gitlab-org/-/epics/19952) dans GitLab 19.0 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `security_scan_profiles_dependency_scanning`. Activés par défaut.
- Profil de remédiation automatique de l'analyse des dépendances [introduit](https://gitlab.com/groups/gitlab-org/-/work_items/604588) dans GitLab 19.2 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `security_remediation_profiles`. Activés par défaut.
- Configuration du profil d'analyse de détection des secrets [introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/606237) dans GitLab 19.3 en tant que [version expérimentale](../../../policy/development_stages_support.md), disponible uniquement via l'API GraphQL.
- Feature flag `security_scan_profiles_feature` supprimé dans GitLab 19.4.
- Feature flag `security_remediation_profiles` supprimé dans GitLab 19.4.
- Configuration du profil d'analyse SAST [introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/617070) dans GitLab 19.4 en tant que [version expérimentale](../../../policy/development_stages_support.md), disponible uniquement via l'API GraphQL.
- Configuration du profil d'analyse des dépendances [introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/629403) dans GitLab 19.5 en tant que [version expérimentale](../../../policy/development_stages_support.md#experiment), disponible uniquement via l'API GraphQL.
- Profils personnalisés dans l'interface utilisateur [introduits](https://gitlab.com/gitlab-org/gitlab/-/work_items/624191) dans GitLab 19.4 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `custom_scan_profiles_ui`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259962) dans GitLab 19.5.

{{< /history >}}

Les profils de configuration de sécurité sont des paramètres centralisés qui définissent comment et quand les scanners de sécurité s'exécutent dans vos projets. Utilisez les profils de configuration de sécurité pour gérer efficacement les scanners de sécurité au sein de votre organisation. Une approche basée sur les profils applique les bonnes pratiques avec une configuration manuelle minimale.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une vue d'ensemble, consultez la vidéo [Présentation des profils de configuration de sécurité](https://www.youtube.com/watch?v=QbnLGzTEqGI).

Lorsque vous appliquez un profil à un groupe, il est appliqué à chaque projet individuel au sein de ce groupe. Les profils ne sont pas attachés au groupe lui-même, et il n'y a pas d'héritage entre les profils ou les sous-groupes.

Utilisez les [profils par défaut](#default-profiles) pour activer le scan de sécurité préconfigurée en quelques minutes et avec une configuration minimale.

## Configurer les scanners de sécurité {#configure-security-scanners}

Pour évaluer et gérer vos profils, utilisez l'[inventaire de sécurité](../security_inventory/_index.md#view-the-security-inventory) de votre groupe comme tableau de bord central.

### Examiner la couverture des tests {#review-test-coverage}

Pour afficher le statut général (**Activé**, **Non activé** ou **Échec**) des scanners du groupe, comme SAST, l'analyse des dépendances et la détection des secrets :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécurisation** > **Inventaire de sécurité**.
1. Dans l'inventaire de sécurité, examinez la colonne **Couverture des tests**.

### Modifier la couverture d'un projet individuel {#change-individual-project-coverage}

Pour configurer un projet spécifique :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécurisation** > **Inventaire de sécurité**.
1. À côté du projet, sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) et sélectionnez **Gérer la couverture des outils**.
1. Activez ou désactivez les scanners individuellement.

### Appliquer un profil à plusieurs projets {#apply-a-profile-to-multiple-projects}

Pour gagner du temps, vous pouvez appliquer des paramètres de sécurité à plusieurs projets en même temps :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécurisation** > **Inventaire de sécurité**.
1. Sélectionnez plusieurs projets ou un sous-groupe entier auxquels appliquer les paramètres.
1. Sélectionnez le menu déroulant **Action groupée** et choisissez **Gérer les scanners de sécurité**.
1. Choisissez **Appliquer le profil par défaut à tous** pour standardiser votre posture de sécurité dans la sélection.

## Profils par défaut {#default-profiles}

GitLab fournit des profils par défaut qui sont des paramètres de scanner préconfigurés afin que vous puissiez activer le scan de sécurité avec une configuration minimale.

### Profil de détection des secrets {#secret-detection-profile}

Lorsque vous appliquez le profil de détection des secrets, vous activez la protection de référence recommandée pour les secrets dans l'ensemble de votre workflow de développement. Le profil active les déclencheurs de scans suivants :

- **Protection contre le push** : scanne tous les événements Git push et bloque les push où des secrets sont détectés, empêchant les secrets d'entrer dans votre base de code.
- **Pipelines de merge request** : exécute automatiquement un scan chaque fois que de nouveaux commits font l'objet d'un push vers une branche avec une merge request ouverte. Les résultats sont limités aux nouvelles vulnérabilités introduites par la merge request. Cible toutes les branches.
- **Pipelines de branche (par défaut seulement)** : s'exécute automatiquement lorsque des modifications sont fusionnées ou font l'objet d'un push vers la branche par défaut, offrant une vue complète de la posture de détection des secrets de votre branche par défaut. Cible toutes les branches.

### Profil SAST {#sast-profile}

Lorsque vous appliquez le profil SAST, vous activez le test statique de sécurité des applications dans vos projets en utilisant la configuration recommandée. Le profil active les déclencheurs de scans suivants :

- **Pipelines de merge request** : exécute automatiquement un scan SAST chaque fois que de nouveaux commits font l'objet d'un push vers une branche avec une merge request ouverte. Les résultats incluent uniquement les nouvelles vulnérabilités introduites par la merge request. Cible toutes les branches.
- **Pipelines de branche (par défaut seulement)** : s'exécute automatiquement lorsque des modifications sont fusionnées ou font l'objet d'un push vers la branche par défaut, offrant une vue complète de la posture SAST de votre branche par défaut. Cible la branche par défaut.

### Profil d'analyse des dépendances {#dependency-scanning-profile}

Lorsque vous activez le profil d'analyse des dépendances, les dépendances de votre projet sont analysées à la recherche de vulnérabilités connues à l'aide de la configuration recommandée. Le profil active les déclencheurs de scans suivants :

- **Pipelines de merge request** : exécute automatiquement une analyse des dépendances chaque fois que de nouveaux commits sont poussés vers une branche avec une merge request ouverte. Les résultats incluent uniquement les nouvelles vulnérabilités introduites par la merge request. Cible toutes les branches.
- **Pipelines de branche (par défaut seulement)** : s'exécute automatiquement lorsque des modifications sont fusionnées ou poussées vers la branche par défaut, fournissant une vue complète de la posture de vulnérabilité des dépendances de votre branche par défaut. Cible la branche par défaut.

### Profil de remédiation automatique de l'analyse des dépendances {#dependency-scanning-auto-remediation-profile}

{{< history >}}

- Prise en charge du profil de triage et de remédiation pour la remédiation automatique [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253780) dans GitLab 19.4 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `triage_and_remediation_profile`. Activés par défaut.

{{< /history >}}

Lorsque vous activez le profil de remédiation automatique de l'analyse des dépendances, GitLab ouvre des merge requests qui mettent à niveau les dépendances vulnérables vers des versions non vulnérables. Pour plus d'informations sur cette fonctionnalité, consultez [la remédiation automatique de l'analyse des dépendances](../remediate/dependency_scanning_auto_remediation.md).

Utilisez le [CLI GitLab](../../../editor_extensions/gitlab_cli/_index.md) (`glab`) pour attacher le profil à un projet :

```shell
glab security config enable dependency_scanning_post_processing -R <project-path>
```

Par exemple, pour activer le profil pour `my-group/my-project` :

```shell
glab security config enable dependency_scanning_post_processing -R my-group/my-project
```

> [!note]
> Un projet peut avoir les deux profils attachés en même temps. Dans ce cas, GitLab utilise uniquement le profil qui a été appliqué en premier. La configuration de l'autre profil est ignorée.

### Profil automatisé de triage et de remédiation {#automated-triage-and-remediation-profile}

{{< history >}}

- Profil de triage et de remédiation [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/622469) dans GitLab 19.4 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `triage_and_remediation_profile`. Activés par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Utilisez le profil de triage et de remédiation pour activer les flows de triage GitLab Duo et la remédiation automatique de l'analyse des dépendances sur les projets et les groupes. Les flows GitLab Duo utilisent l'IA pour évaluer et résoudre les résultats. Un profil peut activer un flow par lui-même ou remplacer le paramètre équivalent par projet, si celui-ci existe.

GitLab propose trois préréglages : conservateur, Standard et Proactif. Chacun applique une configuration différente à chaque flow, ce qui vous permet de choisir dans quelle mesure et à quelle fréquence les flows se déclenchent et s'exécutent. Vous pouvez également créer un profil et le configurer vous-même.

Prérequis :

- Satisfaire aux [prérequis pour GitLab Duo Agent Platform](../../duo_agent_platform/_index.md#prerequisites).
- Activez **Autoriser les flows par défaut** et chaque flow que vous souhaitez utiliser [pour le groupe principal](../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off). Vous activez les flows une seule fois pour le groupe principal, et non pour chaque projet.

> [!note]
> La plupart de ces flows sont alimentés par l'IA et consomment des [GitLab Credits](../../../subscriptions/gitlab_credits.md). La consommation évolue en fonction du nombre de résultats.

#### Préréglages {#presets}

| Flow | Conservateur | Standard | Proactif |
| ---- | ------------ | -------- | --------- |
| Détection des faux positifs SAST | `high` et supérieur, à la demande | `medium` et supérieur, automatique | `info` et supérieur, automatique |
| Résolution des vulnérabilités SAST | `high` et supérieur, à la demande, jusqu'à cinq merge requests ouvertes | `medium` et supérieur, automatique, jusqu'à 15 merge requests ouvertes | `info` et supérieur, automatique, sans limite de merge requests |
| Détection des faux positifs de la détection des secrets | `high` et supérieur, à la demande | `medium` et supérieur, automatique | `info` et supérieur, automatique |
| Remédiation automatique de l'analyse des dépendances | `high` et supérieur, mises à niveau de versions mineures, jusqu'à cinq merge requests ouvertes, ignore les versions correctives des sept derniers jours | `high` et supérieur, mises à niveau de versions mineures, jusqu'à 10 merge requests ouvertes, ignore les versions correctives des sept derniers jours | `info` et supérieur, mises à niveau de versions majeures, jusqu'à 10 merge requests ouvertes, ignore les versions correctives des sept derniers jours |

Pour appliquer un préréglage, utilisez l'[API GraphQL](#apply-a-profile-with-the-graphql-api). Les préréglages sont nommés `Triage and Remediation (Conservative)`, `Triage and Remediation (Standard)` et `Triage and Remediation (Proactive)`.

#### Sujets connexes {#related-topics}

- [Détecter automatiquement les faux positifs](../vulnerabilities/false_positive_detection.md)
- [Résolution agentique des vulnérabilités SAST](../vulnerabilities/agentic_vulnerability_resolution.md)
- [Détection des faux positifs de secrets](../vulnerabilities/secret_false_positive_detection.md)
- [Remédiation automatique de l'analyse des dépendances](../remediate/dependency_scanning_auto_remediation.md)

### Profil de logique métier {#business-logic-profile}

{{< details >}}

- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257199) dans GitLab 19.5 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `bl_security_analyzer`. Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Le profil de logique métier utilise un agent d'IA pour détecter les vulnérabilités de logique métier, comme les autorisations manquantes, les accès défaillants au niveau des objets et les assignations de masse. Lorsque vous attachez le profil à un projet, l'analyse s'active pour ce projet.

Lorsque le pipeline principal d'une merge request réussit, l'analyse s'exécute sur les fichiers que la merge request ajoute ou modifie. Elle ne s'exécute pas sur les pipelines de la branche par défaut. Pour couvrir la branche par défaut, [démarrez une analyse depuis GitLab Duo Chat](../business_logic_scanning/_index.md#start-a-scan-from-gitlab-duo-chat). Si le projet ne dispose d'aucun pipeline CI/CD, aucune analyse de merge request ne s'exécute.

Activez **Autoriser l'exécution du flow**, **Autoriser les flows par défaut** et le flow **Business Logic Security Scan** [pour le groupe principal](../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off).

Pour plus d'informations sur les prérequis et ce que l'analyse détecte, consultez [l'analyse de logique métier](../business_logic_scanning/_index.md).

### Afficher les détails d'un profil {#view-details-about-a-profile}

Pour afficher les détails techniques concernant le profil de détection des secrets :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécurisation** > **Inventaire de sécurité**.
1. Sélectionnez le profil **Détection des secrets**.
1. Examinez les informations suivantes :
   - **Type d'analyseur** : le type de profil (par exemple, **Détection de secret**, **SAST**, **Analyse des dépendances**).
   - **Déclencheurs de scans** : les déclencheurs que le profil prend en charge (par exemple, **protection contre le push**, **pipelines de merge request**, **pipelines de branche**).
   - **Statut** : indique si le profil est actuellement **Actif** ou **Désactivé** pour le contexte actuel à l'aide d'indicateurs de statut de couverture.

## Activer les scanners avec l'assistant d'activation des scanners {#enable-scanners-with-the-scanner-enablement-wizard}

Pour appliquer des profils aux projets qui ne disposent pas de couverture de scanner, utilisez l'[assistant d'activation des scanners](scanner_enablement_wizard.md). L'assistant identifie les projets non couverts et vous permet d'appliquer des profils par défaut ou personnalisés à l'ensemble de votre groupe.

## Appliquer un profil avec l'API GraphQL {#apply-a-profile-with-the-graphql-api}

Utilisez l'API GraphQL pour appliquer n'importe quel profil de configuration de sécurité, y compris les profils qui ne sont pas encore disponibles dans l'interface utilisateur. Vous pouvez exécuter ces requêtes avec l'[explorateur GraphQL interactif](../../../api/graphql/_index.md#interactive-graphql-explorer) ou en envoyant des requêtes directement au point de terminaison `/api/graphql`.

Pour plus d'informations sur l'exécution des requêtes, l'authentification et la pagination, consultez [exécuter des requêtes et des mutations de l'API GraphQL](../../../api/graphql/getting_started.md).

Prérequis :

- Au moins le rôle Maintainer ou le rôle Responsable sécurité pour les projets ou groupes associés.

Pour appliquer un profil de configuration de sécurité :

1. Obtenez les profils disponibles et leurs identifiants pour un groupe :

```graphql
   query {
     group(fullPath: "my-group") {
       availableSecurityScanProfiles {
         id
         name
         scanType
       }
     }
   }
```

   Un profil par défaut qui n'a pas encore été enregistré renvoie un identifiant virtuel basé sur son type d'analyse. Par exemple : `gid://gitlab/Security::ScanProfile/dependency_scanning_post_processing`.

   Pour plus d'informations, consultez le [champ `Group.availableSecurityScanProfiles`](../../../api/graphql/reference/_index.md#groupavailablesecurityscanprofiles).

1. Appliquez le profil avec la mutation `securityScanProfileAttach`, en utilisant l'identifiant virtuel ou l'identifiant réel du profil souhaité :

```graphql
   mutation {
     securityScanProfileAttach(input: {
       securityScanProfileId: "gid://gitlab/Security::ScanProfile/dependency_scanning_post_processing",
       projectIds: ["gid://gitlab/Project/123"]
     }) {
       errors
     }
   }
```

   Pour plus d'informations, consultez la [mutation `securityScanProfileAttach`](../../../api/graphql/reference/_index.md#mutationsecurityscanprofileattach).

1. Pour choisir l'endroit où le profil s'applique, définissez l'un de ces arguments ou les deux :
   - `projectIds` : applique le profil à des projets spécifiques.
   - `groupIds` : applique le profil à tous les projets d'un ou plusieurs groupes.

   Tous les projets et groupes spécifiés doivent appartenir au même groupe principal. Une seule mutation accepte un maximum de 100 identifiants, en comptant les identifiants de projets et de groupes ensemble.

1. Vérifiez le champ `errors` dans la réponse pour confirmer que le profil a été appliqué.

## Personnaliser un profil de détection des secrets {#customize-a-secret-detection-profile}

{{< details >}}

- Statut : version expérimentale

{{< /details >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Personnalisez un profil de détection des secrets pour remplacer la configuration utilisée par le scanner lors de son exécution. Chaque paramètre correspond à une [variable CI/CD de détection des secrets](../secret_detection/_index.md) existante.

Vous pouvez personnaliser un profil de détection des secrets dans l'interface utilisateur ou avec l'API GraphQL.

Prérequis :

- Le rôle Maintainer ou Responsable sécurité pour le groupe associé.

Pour personnaliser un profil de détection des secrets dans l'interface utilisateur :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécurisation** > **Configuration de la sécurité**.
1. Sélectionnez l'onglet **Scanners**.
1. Sur la ligne **Détection de secret**, sélectionnez **Gérer les profils**.
1. Sélectionnez **Créer un nouveau profil**.
1. Saisissez un **Nom** et une **Description**.
1. Sous **Déclencheurs d'analyse**, activez les déclencheurs souhaités.
1. Facultatif. Sous **Configuration avancée**, ajoutez les paramètres à remplacer.
1. Sélectionnez **Créer le profil**.

Pour modifier un profil ultérieurement, sélectionnez-le, puis sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) > **Modifier**, puis **Enregistrer les modifications**. Les modifications s'appliquent à chaque projet qui utilise le profil.

Pour personnaliser un profil de détection des secrets avec l'API GraphQL, utilisez la mutation `securityScanProfileCreate` ou `securityScanProfileUpdate`. Définissez un objet `configuration.secretDetection` sur le déclencheur que vous souhaitez personnaliser.

| Champ | Paramètre de l'interface utilisateur | Description | Variable CI/CD équivalente |
| ----- | ---------- | ----------- | ------------------------- |
| `secureAnalyzersPrefix` | **Registre d'images de l'analyseur** | Préfixe du registre de conteneurs à partir duquel l'image de l'analyseur est extraite. | `SECURE_ANALYZERS_PREFIX` |
| `imageSuffix` | **Variante d'image** (Default, FIPS) | Suffixe ajouté au nom de l'image de l'analyseur. Définir sur `DEFAULT` ou `FIPS`. | `SECRET_DETECTION_IMAGE_SUFFIX` |
| `historicScan` | **Analyse historique** | Indique si l'intégralité de l'historique Git doit être analysée plutôt que l'état actuel uniquement. | `SECRET_DETECTION_HISTORIC_SCAN` |
| `logOptions` | **Options de log** | Options transmises à `git log` pour contrôler la plage de commits analysée. | `SECRET_DETECTION_LOG_OPTIONS` |
| `excludedPaths` | **Chemins à exclure** | Chemins Glob exclus de l'analyse. | `SECRET_DETECTION_EXCLUDED_PATHS` |
| `rulesetGitReference` | **Référence Git de l'ensemble de règles** | Référence Git de la configuration d'ensemble de règles distante à utiliser. | `SECRET_DETECTION_RULESET_GIT_REFERENCE` |

Par exemple, pour créer un profil de détection des secrets avec un déclencheur de pipeline de merge request personnalisé :

```graphql
mutation {
  securityScanProfileCreate(input: {
    namespaceId: "gid://gitlab/Group/123",
    scanType: SECRET_DETECTION,
    name: "Custom secret detection profile",
    description: "Secret detection profile with a historic scan and path exclusions",
    triggers: [
      {
        triggerType: MERGE_REQUEST_PIPELINE,
        configuration: {
          secretDetection: {
            historicScan: true,
            excludedPaths: ["spec/**/*", "test/**/*"]
          }
        }
      }
    ]
  }) {
    scanProfile {
      id
      name
    }
    errors
  }
}
```

Par défaut, l'argument `stripDefaults` supprime les valeurs de configuration de déclencheur qui correspondent aux valeurs par défaut avant d'enregistrer le profil, de sorte que seules vos personnalisations sont conservées.

Pour la liste complète des arguments, consultez la [mutation `securityScanProfileCreate`](../../../api/graphql/reference/_index.md#mutationsecurityscanprofilecreate).

## Personnaliser un profil SAST {#customize-a-sast-profile}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Personnalisez un profil SAST pour remplacer la configuration du scanner utilisée lors de l'exécution du profil. Chaque paramètre correspond à une [variable CI/CD SAST](../sast/_index.md) existante.

Cette fonctionnalité est une [version expérimentale](../../../policy/development_stages_support.md). Vous pouvez personnaliser un profil SAST dans l'interface utilisateur ou avec l'API GraphQL.

Prérequis :

- Le rôle Maintainer ou Responsable sécurité pour le groupe associé.

Pour personnaliser un profil SAST dans l'interface utilisateur :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécurisation** > **Configuration de la sécurité**.
1. Sélectionnez l'onglet **Scanners**.
1. Sur la ligne **Test de sécurité statique d'application (SAST)**, sélectionnez **Gérer les profils**.
1. Sélectionnez **Créer un nouveau profil**.
1. Saisissez un **Nom** et une **Description**.
1. Sous **Déclencheurs d'analyse**, activez les déclencheurs souhaités.
1. Facultatif. Sous **Configuration avancée**, ajoutez les paramètres à remplacer.
1. Sélectionnez **Créer le profil**.

Pour modifier un profil ultérieurement, sélectionnez-le, puis sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) > **Modifier**, puis **Enregistrer les modifications**. Les modifications s'appliquent à chaque projet qui utilise le profil.

Pour personnaliser un profil SAST avec l'API GraphQL, utilisez la mutation `securityScanProfileCreate` ou `securityScanProfileUpdate`. Définissez un objet `configuration.sast` sur le déclencheur que vous souhaitez personnaliser.

| Champ | Paramètre de l'interface utilisateur | Description | Variable CI/CD équivalente |
| ----- | ---------- | ----------- | ------------------------- |
| `secureAnalyzersPrefix` | **Registre d'images de l'analyseur** | Préfixe du registre de conteneurs à partir duquel l'image de l'analyseur est extraite. | `SECURE_ANALYZERS_PREFIX` |
| `imageSuffix` | **Variante d'image** (Default, FIPS) | Suffixe ajouté au nom de l'image de l'analyseur. Définir sur `DEFAULT` ou `FIPS`. | `SAST_IMAGE_SUFFIX` |
| `analyzerImageTag` | **Tag de l'image de l'analyseur** | Tag de l'image de l'analyseur à utiliser. Remplace le tag d'image épinglé pour tous les analyseurs SAST, ce qui peut entraîner des échecs de l'analyseur si une version spécifique est requise. | `SAST_ANALYZER_IMAGE_TAG` |
| `excludedAnalyzers` | **Analyseurs à ignorer** | Analyseurs exclus de l'analyse. | `SAST_EXCLUDED_ANALYZERS` |
| `excludedPaths` | **Chemins à exclure** | Chemins Glob exclus de l'analyse. | `SAST_EXCLUDED_PATHS` |
| `advancedSastPartialScan` | **Analyse partielle SAST avancée** (Activé, Désactivé) | Contrôle l'[analyse basée sur les différences](../sast/gitlab_advanced_sast.md) pour GitLab Advanced SAST. Définir sur `DIFFERENTIAL` ou `DISABLED`. | `ADVANCED_SAST_PARTIAL_SCAN` |
| `gitlabAdvSastIncrScan` | **Analyse incrémentielle SAST avancée** | Indique si l'[analyse incrémentielle](../sast/gitlab_advanced_sast.md) est activée pour GitLab Advanced SAST. | `GITLAB_ADV_SAST_INCR_SCAN` |

Par exemple, pour créer un profil SAST avec un déclencheur de pipeline de merge request personnalisé :

```graphql
mutation {
  securityScanProfileCreate(input: {
    namespaceId: "gid://gitlab/Group/123",
    scanType: SAST,
    name: "Custom SAST profile",
    description: "SAST profile with custom analyzer exclusions and Advanced SAST settings",
    triggers: [
      {
        triggerType: MERGE_REQUEST_PIPELINE,
        configuration: {
          sast: {
            excludedAnalyzers: ["eslint"],
            excludedPaths: ["spec/**/*", "test/**/*"],
            advancedSastPartialScan: DIFFERENTIAL,
            gitlabAdvSastIncrScan: true
          }
        }
      }
    ]
  }) {
    scanProfile {
      id
      name
    }
    errors
  }
}
```

Vous ne pouvez définir qu'un seul membre de configuration par déclencheur, et il doit correspondre au type d'analyse du profil. Pour un profil SAST, ce membre est `sast`.

Par défaut, l'argument `stripDefaults` supprime les valeurs de configuration de déclencheur qui correspondent aux valeurs par défaut avant d'enregistrer le profil, de sorte que seules vos personnalisations sont conservées.

Pour la liste complète des arguments, consultez la [mutation `securityScanProfileCreate`](../../../api/graphql/reference/_index.md#mutationsecurityscanprofilecreate).

## Personnaliser un profil d'analyse des dépendances {#customize-a-dependency-scanning-profile}

{{< details >}}

- Statut : version expérimentale

{{< /details >}}

Personnalisez un profil d'analyse des dépendances pour remplacer la configuration utilisée par le scanner lors de son exécution. Chaque paramètre correspond à une [variable CI/CD d'analyse des dépendances](../dependency_scanning/dependency_scanning_sbom/_index.md) existante.

Cette fonctionnalité est disponible uniquement via l'API GraphQL.

Prérequis :

- Le rôle Responsable sécurité, Maintainer ou Owner pour le groupe principal.

Pour personnaliser un profil d'analyse des dépendances :

- Dans la mutation `securityScanProfileCreate` ou `securityScanProfileUpdate`, définissez un objet `configuration.dependencyScanning` sur chaque déclencheur que vous souhaitez personnaliser.

L'objet `dependencyScanning` prend en charge les champs suivants :

| Champ | Description | Variable CI/CD équivalente |
| ----- | ----------- | ------------------------- |
| `secureAnalyzersPrefix` | Préfixe du registre de conteneurs à partir duquel l'image de l'analyseur est extraite. | `SECURE_ANALYZERS_PREFIX` |
| `additionalCaCertBundle` | Ensemble de certificats CA à considérer comme fiables. Le bundle est ajouté aux certificats du système et utilisé par d'autres outils pendant l'analyse. | `ADDITIONAL_CA_CERT_BUNDLE` |
| `secureLogLevel` | Niveau de journalisation utilisé par l'analyseur. Définir sur `FATAL`, `ERROR`, `WARN`, `INFO` ou `DEBUG`. | `SECURE_LOG_LEVEL` |
| `excludedPaths` | Chemins Glob exclus de l'analyse. | `DS_EXCLUDED_PATHS` |
| `includeDevDependencies` | Indique si les dépendances de développement et de test doivent être incluses lors de l'analyse d'un fichier pris en charge. | `DS_INCLUDE_DEV_DEPENDENCIES` |
| `maxDepth` | Profondeur de répertoire analysée par l'analyseur. Une valeur de `-1` analyse tous les répertoires. | `DS_MAX_DEPTH` |
| `pipDependencyPath` | Chemin utilisé pour installer les paquets Python pour l'analyse. | `DS_PIP_DEPENDENCY_PATH` |
| `staticReachabilityEnabled` | Indique si la [portée statique](../dependency_scanning/static_reachability.md) est activée. | `DS_STATIC_REACHABILITY_ENABLED` |
| `enableManifestFallback` | Indique si les fichiers manifestes doivent être analysés lorsqu'aucun fichier de verrouillage ou export de graphe de dépendances n'est disponible. Pour plus d'informations, consultez [le repli sur le manifeste](../dependency_scanning/dependency_scanning_sbom/_index.md#manifest-fallback). | `DS_ENABLE_MANIFEST_FALLBACK` |
| `pipcompileLockfileFileNamePattern` | Modèle Glob qui sélectionne les fichiers de verrouillage pip-compile à traiter. Le modèle correspond uniquement aux noms de fichiers, pas aux chemins de répertoire. | `DS_PIPCOMPILE_LOCKFILE_FILE_NAME_PATTERN` |
| `pipManifestFileNamePattern` | Modèle Glob qui sélectionne les fichiers manifestes pip à traiter pour la résolution des dépendances et l'analyse des manifestes. Le modèle correspond uniquement aux noms de fichiers, pas aux chemins de répertoire. | `DS_PIP_MANIFEST_FILE_NAME_PATTERN` |
| `enableVulnerabilityScan` | Indique si l'analyse des vulnérabilités des SBOM générés est activée. | `DS_ENABLE_VULNERABILITY_SCAN` |
| `apiTimeout` | Délai d'expiration des requêtes de l'API d'analyse des vulnérabilités en secondes, de 5 à 300. | `DS_API_TIMEOUT` |
| `apiScanDownloadDelay` | Délai initial en secondes de l'API d'analyse des vulnérabilités avant le téléchargement des résultats d'analyse, de 1 à 120. | `DS_API_SCAN_DOWNLOAD_DELAY` |
| `mavenDependencyPluginVersion` | Version de `maven-dependency-plugin` utilisée lors de la résolution. | `DS_MAVEN_DEPENDENCY_PLUGIN_VERSION` |
| `mavenArgs` | Arguments supplémentaires transmis à Maven lors de la résolution des dépendances. | `MAVEN_ARGS` |
| `gradleCliOpts` | Options de ligne de commande supplémentaires transmises à Gradle lors de la résolution des dépendances. | `GRADLE_CLI_OPTS` |
| `disabledResolutionJobs` | Liste des jobs de résolution à désactiver. Les valeurs valides sont `MAVEN`, `GRADLE` et `PYTHON`. Par défaut, tous les jobs de résolution disponibles sont activés. | `DS_DISABLED_RESOLUTION_JOBS` |
| `mavenResolutionImage` | Image utilisée par le job de résolution des dépendances Maven. | `DS_MAVEN_RESOLUTION_IMAGE` |
| `gradleResolutionImage` | Image utilisée par le job de résolution des dépendances Gradle. | `DS_GRADLE_RESOLUTION_IMAGE` |
| `pythonResolutionImage` | Image utilisée par le job de résolution des dépendances Python. | `DS_PYTHON_RESOLUTION_IMAGE` |
| `pipIndexUrl` | URL de base de l'index de paquets Python. | `PIP_INDEX_URL` |
| `pipExtraIndexUrl` | URL supplémentaires des index de paquets Python à utiliser en plus de `pipIndexUrl`. | `PIP_EXTRA_INDEX_URL` |
| `searchIgnoreHiddenDirs` | Indique si les répertoires cachés doivent être ignorés lorsque l'analyseur recherche les fichiers pris en charge. | `SEARCH_IGNORE_HIDDEN_DIRS` |

Par exemple, pour créer un profil d'analyse des dépendances avec un déclencheur de pipeline de merge request personnalisé :

```graphql
mutation {
  securityScanProfileCreate(input: {
    namespaceId: "gid://gitlab/Group/123",
    scanType: DEPENDENCY_SCANNING,
    name: "Custom dependency scanning profile",
    description: "Dependency scanning profile that excludes development dependencies and scans all directories",
    triggers: [
      {
        triggerType: MERGE_REQUEST_PIPELINE,
        configuration: {
          dependencyScanning: {
            includeDevDependencies: false,
            excludedPaths: ["spec/**/*", "test/**/*"],
            maxDepth: -1,
            staticReachabilityEnabled: true
          }
        }
      }
    ]
  }) {
    scanProfile {
      id
      name
    }
    errors
  }
}
```

Vous ne pouvez définir qu'un seul membre de configuration par déclencheur, et il doit correspondre au type d'analyse du profil. Pour un profil d'analyse des dépendances, ce membre est `dependencyScanning`.

Pour la liste complète des arguments, consultez la [mutation `securityScanProfileCreate`](../../../api/graphql/reference/_index.md#mutationsecurityscanprofilecreate).

## Indicateurs de statut de couverture {#coverage-status-indicators}

Le système utilise des repères visuels dans l'inventaire pour indiquer si vos projets sont protégés :

- **Barre verte pleine** : le scanner est entièrement activé et actif.
- **Barre grise/vide** : le scanner n'est pas encore configuré ou activé.
- **Barre partielle** : une partie de la protection est active (par exemple, certains déclencheurs disponibles dans le profil sont activés, mais d'autres ne le sont pas).
- **Infobulles** : survolez n'importe quelle barre de couverture pour afficher la date de la dernière analyse pour les analyses basées sur les pipelines et le statut spécifique du pipeline.

Contrairement aux scans basés sur les pipelines, la protection contre le push n'a pas de date de dernier scan, car elle s'exécute en temps réel pendant le processus de push.

## Dépannage {#troubleshooting}

Lorsque vous travaillez avec des profils de configuration de sécurité, vous pouvez rencontrer les problèmes suivants.

### Aucune date de dernier scan n'apparaît pour la protection contre le push {#no-last-scan-date-appears-for-push-protection}

La protection contre le push est basée sur les événements, et non sur une planification. Elle intercepte les secrets en temps réel pendant le processus `git push`. Étant donné qu'elle est active au moment de la commande `push`, il n'y a pas de date de dernier scan comme vous pourriez en attendre avec des scanners basés sur les pipelines.

### Le statut du scanner est actif dans le tableau de bord mais n'est pas activé dans l'infobulle de l'inventaire {#scanner-status-is-active-in-the-dashboard-but-not-enabled-in-inventory-tooltip}

Cela peut se produire lorsqu'un projet utilise des paramètres hérités tout en se voyant attribuer un nouveau profil.

Pour résoudre ce problème :

1. Vérifiez la page **Configuration de sécurité** pour obtenir l'état de profil actuel le plus précis.
1. Si nécessaire, supprimez les configurations de scanner héritées de votre fichier `.gitlab-ci.yml` pour vous reposer uniquement sur la configuration basée sur les profils.

> [!note]
> L'infobulle de l'inventaire est en cours d'amélioration afin de refléter le statut combiné des paramètres hérités et basés sur les profils.

### Comprendre la configuration héritée par rapport à la configuration basée sur les profils {#understanding-legacy-versus-profile-based-configuration}

Si vous migrez d'une configuration de scanner héritée vers une configuration basée sur les profils, notez les différences suivantes :

- Configuration héritée : nécessite des modifications manuelles de vos fichiers YAML ou des paramètres de projet individuels pour activer les scanners.
- Configuration basée sur les profils : utilise un système centralisé qui vous permet d'appliquer un profil par défaut à plusieurs projets en même temps sans modifier le code.

La configuration basée sur les profils est recommandée pour une gestion plus facile et une meilleure cohérence entre les projets.
