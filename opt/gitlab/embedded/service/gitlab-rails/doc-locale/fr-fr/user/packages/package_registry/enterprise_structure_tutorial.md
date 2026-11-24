---
stage: Package
group: Package Registry
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
title: 'Tutoriel : structurer le registre de paquets pour une utilisation à l''échelle de l''entreprise'
---

À mesure que votre organisation se développe, la gestion des paquets peut devenir de plus en plus complexe. Le modèle de registre de paquets GitLab offre une solution puissante pour la gestion des paquets en entreprise. Comprendre comment exploiter le registre de paquets est essentiel pour travailler avec les paquets de manière sécurisée, simple et à grande échelle.

Dans ce tutoriel, vous apprendrez à intégrer le modèle de registre de paquets GitLab dans une structure de groupe d'entreprise. Bien que les exemples fournis ici soient spécifiques aux paquets Maven et npm, vous pouvez étendre les concepts de ce tutoriel à tout paquet pris en charge par le registre de paquets GitLab.

À la fin de ce tutoriel, vous saurez comment :

1. [Configurer un groupe racine ou groupe principal unique pour structurer votre travail](#create-an-enterprise-structure).
1. [Configurer des projets pour la publication de paquets avec une propriété claire](#set-up-a-top-level-group).
1. [Configurer la consommation de paquets au niveau du groupe principal pour un accès simplifié](#publish-packages).
1. [Ajouter des jetons de déploiement pour que votre équipe puisse accéder aux paquets de votre organisation](#add-deploy-tokens).
1. [Configurer CI/CD pour utiliser vos paquets de manière sécurisée](#use-packages-with-cicd).

## Avant de commencer {#before-you-begin}

Vous aurez besoin des éléments suivants pour suivre ce tutoriel :

- Un paquet npm ou Maven.
- Une connaissance du registre de paquets GitLab.
- Un projet de test. Vous pouvez utiliser un projet existant ou en créer un pour ce tutoriel.

## Comprendre le registre de paquets GitLab {#understand-the-gitlab-package-registry}

Les gestionnaires de paquets traditionnels comme JFrog Artifactory et Sonatype Nexus utilisent un dépôt unique et centralisé pour stocker et mettre à jour vos paquets. Avec GitLab, vous gérez les paquets directement dans votre groupe ou projet. Cela signifie que :

- Les équipes publient des paquets dans des projets qui stockent du code.
- Les équipes consomment des paquets à partir des registres du groupe racine qui agrègent tous les paquets qui leur sont subordonnés.
- Le contrôle d'accès est hérité de vos autorisations GitLab existantes.

Étant donné que vos paquets sont stockés et gérés comme du code, vous pouvez ajouter la gestion des paquets à vos projets ou groupes existants. Ce modèle offre plusieurs avantages :

- Propriété claire des paquets aux côtés de leur code source
- Contrôle d'accès granulaire sans configuration supplémentaire
- Intégration CI/CD simplifiée
- Alignement naturel avec les structures d'équipe
- URL unique pour accéder à tous les paquets de l'entreprise via la consommation au niveau du groupe racine

## Créer une structure d'entreprise {#create-an-enterprise-structure}

Envisagez d'organiser votre code sous un seul groupe principal. Par exemple :

```plaintext
company/ (top-level group)
├── retail-division/
│   ├── shared-libraries/    # Division-specific shared code
│   └── teams/
│       ├── checkout/        # Team publishes packages here
│       └── inventory/       # Team publishes packages here
├── banking-division/
│   ├── shared-libraries/    # Division-specific shared code
│   └── teams/
│       ├── payments/        # Team publishes packages here
│       └── fraud/           # Team publishes packages here
└── shared-platform/         # Enterprise-wide shared code
    ├── java-commons/        # Shared Java libraries
    └── ui-components/       # Shared UI components
```

Dans cette structure, toutes les équipes d'une entreprise publient du code et des paquets dans leurs propres projets, tout en héritant des configurations du groupe `company/` principal.

## Configurer un groupe principal {#set-up-a-top-level-group}

Vous pouvez utiliser un groupe principal existant si vous en avez un et si vous disposez du rôle Propriétaire.

Si vous n'avez pas de groupe, créez-en un :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau groupe**.
1. Dans **Nom du groupe**, saisissez un nom pour le groupe.
1. Dans **URL du groupe**, saisissez un chemin pour le groupe, qui est utilisé comme espace de nommage.
1. Choisissez le [niveau de visibilité](../../public_access.md).
1. Facultatif. Renseignez les informations pour personnaliser votre expérience.
1. Sélectionnez **Créer un groupe**.

Ce groupe stockera les autres groupes et projets de votre organisation. Si vous avez d'autres projets et groupes, vous pouvez [les transférer vers le nouveau groupe principal](../../group/manage.md#transfer-a-group) pour les gérer.

Avant de continuer, assurez-vous d'avoir au moins :

- Un groupe principal.
- Un projet qui appartient au groupe principal ou à l'un de ses sous-groupes.

## Publier des paquets {#publish-packages}

Pour maintenir une propriété claire, les équipes doivent publier leurs paquets dans leurs propres registres de paquets. Cela permet de conserver les paquets avec leur code source et de s'assurer que l'historique des versions est lié à l'activité du projet.

{{< tabs >}}

{{< tab title="Projets Maven" >}}

Pour publier des paquets Maven :

- Configurez votre fichier `pom.xml` pour publier dans le registre de paquets du projet :

  ```xml
  <!-- checkout/pom.xml -->
  <distributionManagement>
      <repository>
          <id>gitlab-maven</id>
          <url>${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/maven</url>
      </repository>
  </distributionManagement>
  ```

{{< /tab >}}

{{< tab title="Projets npm" >}}

Pour publier des paquets npm :

- Configurez votre fichier `package.json` :

  ```json
  // ui-components/package.json
  {
    "name": "@company/ui-components",
    "publishConfig": {
      "registry": "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/npm/"
    }
  }
  ```

{{< /tab >}}

{{< /tabs >}}

## Consommer des paquets {#consume-packages}

Étant donné que vos projets sont organisés sous un seul groupe principal, vos paquets restent accessibles à l'organisation. Configurons un point de terminaison d'API unique pour que vos équipes puissent consommer des paquets.

{{< tabs >}}

{{< tab title="Projets Maven" >}}

- Configurez votre `pom.xml` pour accéder aux paquets du groupe principal :

  ```xml
  <!-- Any project's pom.xml -->
  <repositories>
      <repository>
          <id>gitlab-maven</id>
          <url>https://gitlab.example.com/api/v4/groups/company/-/packages/maven</url>
      </repository>
  </repositories>
  ```

{{< /tab >}}

{{< tab title="Projets npm" >}}

- Configurez votre fichier `.npmrc` :

  ```shell
  # Any project's .npmrc
  @company:registry=https://gitlab.example.com/api/v4/groups/company/-/packages/npm/
  ```

{{< /tab >}}

{{< /tabs >}}

Cette configuration fournit automatiquement l'accès à tous les paquets de votre organisation tout en maintenant les avantages de la publication par projet.

## Ajouter des jetons de déploiement {#add-deploy-tokens}

Ensuite, ajoutez un jeton de déploiement en lecture seule. Ce jeton fournit l'accès aux paquets stockés dans les sous-groupes et les projets de l'organisation, afin que vos équipes puissent les utiliser pour le développement.

1. Dans votre groupe principal, dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Jetons de déploiement**.
1. Sélectionnez **Ajouter un jeton**.
1. Renseignez les champs et définissez la portée sur `read_repository`.
1. Sélectionnez **Créer un jeton de déploiement**.

Vous pouvez ajouter autant de jetons de déploiement que nécessaire à votre groupe principal. N'oubliez pas de renouveler vos jetons périodiquement. Si vous suspectez qu'un jeton a été compromis, révoquez-le et remplacez-le immédiatement.

## Utiliser des paquets avec CI/CD {#use-packages-with-cicd}

Lorsque les jobs CI/CD ont besoin d'accéder au registre de paquets, ils s'authentifient avec la variable CI/CD prédéfinie `CI_JOB_TOKEN`. Cette authentification s'effectue automatiquement, vous n'avez donc pas besoin d'effectuer de configuration supplémentaire :

```yaml
publish:
  script:
    - mvn deploy  # For Maven packages
    # or
    - npm publish # For npm packages
  # CI_JOB_TOKEN provides automatic authentication
```

## Résumé et prochaines étapes {#summary-and-next-steps}

L'organisation de vos projets GitLab sous un seul groupe principal confère plusieurs avantages :

- Configuration simplifiée :
  - Une URL unique pour l'accès à tous les paquets
  - Configuration cohérente entre les équipes
  - Renouvellement facile des jetons
- Propriété claire :
  - Les paquets restent liés à leur code source
  - Les équipes conservent le contrôle sur la publication
  - L'historique des versions est lié à l'activité du projet
- Organisation naturelle :
  - Vos groupes correspondent à la structure de votre entreprise
  - Les équipes peuvent collaborer tout en restant autonomes

Le modèle de registre de paquets GitLab offre une solution puissante pour la gestion des paquets en entreprise. En combinant la publication par projet avec la consommation au niveau du groupe principal, vous bénéficiez du meilleur des deux approches : une propriété claire et un accès simplifié.

Cette approche s'adapte naturellement à votre organisation tout en maintenant la sécurité et la facilité d'utilisation. Commencez par implémenter ce modèle avec une seule équipe ou division, puis développez-le au fur et à mesure que vous constatez les avantages de cette approche intégrée. N'oubliez pas que bien que ce tutoriel se soit concentré sur Maven et npm, les mêmes principes s'appliquent à tous les types de paquets pris en charge par GitLab.
