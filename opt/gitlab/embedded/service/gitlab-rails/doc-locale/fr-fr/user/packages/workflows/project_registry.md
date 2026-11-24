---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Gérer les paquets avec des registres dédiés et spécifiques à chaque type
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Organisez vos paquets par type dans des projets dédiés au sein d'un groupe principal de gestion des artefacts. Cette approche offre une propriété claire et des politiques spécifiques à chaque type.

Utilisez cette approche lorsque vous souhaitez :

- Organiser les paquets par type avec des politiques et des paramètres dédiés.
- Fournir un point de consommation unique pour tous les paquets de l'organisation.
- Migrer des paquets depuis des registres tiers vers une configuration GitLab structurée.
- Séparer les préoccupations de gestion des paquets du code source de l'application.
- Appliquer différentes politiques de gouvernance à différents types de paquets.
- Maintenir une propriété claire tout en permettant un accès à l'échelle de l'organisation.

## Exemple de procédure pas à pas {#example-walkthrough}

Pour organiser et gérer efficacement vos paquets avec cette approche, vous devez :

- Créer un groupe principal dédié à la gestion des artefacts avec des projets organisés par type de paquet.
- Limiter le groupe principal aux seuls projets contenant des artefacts afin d'améliorer les performances lors de la consommation des paquets.

### Structure recommandée {#recommended-structure}

L'exemple suivant fournit un aperçu de la façon dont vous devez structurer votre groupe principal et vos projets :

```plaintext
company_namespace/artifact_management/ # top-level group
├── java-packages/           # Maven packages
├── node-packages/           # npm packages
├── python-packages/         # PyPI packages
├── docker-images/           # Container registry
├── terraform-modules/       # Terraform modules
├── nuget-packages/          # NuGet packages
└── generic-packages/        # Generic file packages
```

> [!note]
> Certaines organisations préfèrent une séparation supplémentaire en fonction du cycle de vie ou de la stabilité des paquets. Par exemple, vous pouvez créer des projets distincts pour `java-releases/` et `java-snapshots/`. De cette façon, vous pouvez appliquer différentes politiques de nettoyage, contrôles d'accès ou workflows d'approbation pour les paquets stables et les paquets en développement.

### Créer le groupe et les projets {#create-the-group-and-projects}

Créez un nouveau groupe principal pour la gestion des artefacts :

1. Dans la barre supérieure, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau groupe**.
1. Sélectionnez **Créer un groupe**.
1. Dans la zone de texte **Nom du groupe**, saisissez `Artifact Management` ou un nom similaire.
1. Dans **URL du groupe**, conservez le chemin généré.
1. Sélectionnez le [**Niveau de visibilité**](../../public_access.md) du groupe.
1. Sélectionnez **Créer un groupe**.

Créez des projets pour chaque type de paquet dont vous avez besoin :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre groupe de gestion des artefacts.
1. Dans la barre latérale gauche, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer un projet vide**.
1. Saisissez un **Nom du projet** pour le type de paquet souhaité. Par exemple, `java-packages` ou `node-packages`.
1. Définissez le niveau de visibilité approprié.
1. Sélectionnez **Créer le projet**.

Commencez par les types de paquets les plus utilisés par votre organisation, puis développez la structure au fur et à mesure que vous adoptez des formats de paquets supplémentaires. Cette approche s'adapte naturellement tout en maintenant la sécurité et la facilité d'utilisation.

Configurez les paramètres du groupe :

1. Dans votre groupe de gestion des artefacts, dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Configurez les politiques de groupe dont vous avez besoin, comme **Paquets dupliqués** ou **Transfert de paquet**.
1. Configurez les contrôles d'accès du groupe selon vos besoins.

## Configurer l'authentification et l'accès {#configure-authentication-and-access}

L'authentification varie en fonction de votre cas d'utilisation. Consultez les suggestions ci-dessous. Pour plus d'informations sur l'authentification, voir [S'authentifier auprès du registre](../package_registry/supported_functionality.md#authenticate-with-the-registry)

Pour le développement local (développeurs) :

- Jetons d'accès personnels pour les développeurs individuels
- Jetons d'accès de groupe pour les informations d'identification partagées de l'équipe

Pour les pipelines CI/CD :

- Jetons de job CI/CD (préférés) - authentification automatique
- Jetons d'accès au projet pour les cas particuliers

Pour les systèmes externes :

- Jetons de déploiement pour la consommation en lecture seule
- Jetons d'accès au projet et de groupe pour un contrôle plus granulaire

### Configurer l'accès au groupe principal {#set-up-top-level-group-access}

Créez un jeton de déploiement de groupe pour la consommation de paquets à l'échelle de l'organisation :

1. Dans votre groupe de gestion des artefacts, dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Jetons de déploiement**.
1. Sélectionnez **Ajouter un jeton** et remplissez les champs :
   - Pour le **Nom**, saisissez `package-consumption`.
   - Pour les **Périmètre d'accès**, sélectionnez `read_package_registry`.
1. Sélectionnez **Créer un jeton de déploiement**.

Enregistrez le jeton en lieu sûr.

Si vous souhaitez utiliser des jetons de job CI/CD pour la publication, configurez la liste d'autorisation des jetons de job :

1. Dans chaque projet spécifique au type de paquet, dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD**.
1. Développez **Accès aux jetons**.
1. Ajoutez les projets qui doivent être autorisés à publier des paquets dans ce registre de paquets.

### Configurer les paramètres du projet {#configure-project-settings}

Pour chaque projet de type de paquet, configurez :

- **Politiques de cycle de vie** appropriées pour ce type de paquet
- Règles de **Paquets protégés**, si nécessaire
- Règles de **Tags de conteneur protégés**, si nécessaire
- **Jetons d'accès projet** pour des cas d'utilisation spécifiques

## Publier des paquets {#publish-packages}

Les équipes doivent publier les paquets dans le registre de projet spécifique au type approprié. Consultez les exemples suivants pour chaque format de paquet pris en charge.

{{< tabs >}}

{{< tab title="Maven" >}}

Configurez le fichier `pom.xml` de votre projet pour publier dans le projet `java-packages` :

```xml
<distributionManagement>
    <repository>
        <id>gitlab-maven</id>
        <url>${CI_API_V4_URL}/projects/JAVA_PACKAGES_PROJECT_ID/packages/maven</url>
    </repository>
    <snapshotRepository>
        <id>gitlab-maven</id>
        <url>${CI_API_V4_URL}/projects/JAVA_PACKAGES_PROJECT_ID/packages/maven</url>
    </snapshotRepository>
</distributionManagement>
```

Configurez l'authentification dans votre `settings.xml` :

```xml
<servers>
    <server>
        <id>gitlab-maven</id>
        <configuration>
            <httpHeaders>
                <property>
                    <name>Job-Token</name>
                    <value>${CI_JOB_TOKEN}</value>
                </property>
            </httpHeaders>
        </configuration>
    </server>
</servers>
```

Publiez avec :

```shell
mvn deploy
```

{{< /tab >}}

{{< tab title="npm" >}}

Configurez le fichier `package.json` de votre projet :

```json
{
  "name": "@company/my-package",
  "publishConfig": {
    "registry": "${CI_API_V4_URL}/projects/NODE_PACKAGES_PROJECT_ID/packages/npm/"
  }
}
```

Pour la publication CI/CD, le jeton de job est utilisé automatiquement :

```yaml
publish:
  script:
    - npm publish
```

Pour la publication en local, configurez l'authentification :

```shell
npm config set @company:registry https://gitlab.example.com/api/v4/projects/NODE_PACKAGES_PROJECT_ID/packages/npm/
npm config set //gitlab.example.com/api/v4/projects/NODE_PACKAGES_PROJECT_ID/packages/npm/:_authToken ${PERSONAL_ACCESS_TOKEN}
```

{{< /tab >}}

{{< tab title="PyPI" >}}

Configurez la publication dans votre pipeline CI/CD :

```yaml
publish:
  script:
    - pip install build twine
    - python -m build
    - TWINE_PASSWORD=${CI_JOB_TOKEN} TWINE_USERNAME=gitlab-ci-token twine upload --repository-url ${CI_API_V4_URL}/projects/PYTHON_PACKAGES_PROJECT_ID/packages/pypi dist/*
```

Pour la publication en local :

```shell
twine upload --repository-url https://gitlab.example.com/api/v4/projects/PYTHON_PACKAGES_PROJECT_ID/packages/pypi --username __token__ --password ${PERSONAL_ACCESS_TOKEN} dist/*
```

{{< /tab >}}

{{< tab title="Registre de conteneurs" >}}

Créez et poussez des images Docker :

```yaml
build-image:
  script:
    - docker build -t $CI_REGISTRY/artifact-management/docker-images/my-app:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY/artifact-management/docker-images/my-app:$CI_COMMIT_SHA
```

Pour le développement local :

```shell
docker login gitlab.example.com -u ${USERNAME} -p ${PERSONAL_ACCESS_TOKEN}
docker push gitlab.example.com/artifact-management/docker-images/my-app:latest
```

{{< /tab >}}

{{< tab title="Terraform" >}}

Publiez des modules Terraform :

```yaml
publish-module:
  script:
    - tar -czf module.tar.gz *.tf
    - 'curl --header "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file module.tar.gz "${CI_API_V4_URL}/projects/TERRAFORM_PACKAGES_PROJECT_ID/packages/terraform/modules/my-module/my-provider/1.0.0/file"'
```

{{< /tab >}}

{{< tab title="NuGet" >}}

Configurez la publication dans le fichier de votre projet ou dans votre pipeline CI/CD :

```yaml
publish:
  script:
    - dotnet pack
    - dotnet nuget push "bin/Release/*.nupkg" --source ${CI_API_V4_URL}/projects/NUGET_PACKAGES_PROJECT_ID/packages/nuget/index.json --api-key ${CI_JOB_TOKEN}
```

Pour la publication en local :

```shell
dotnet nuget push package.nupkg --source https://gitlab.example.com/api/v4/projects/NUGET_PACKAGES_PROJECT_ID/packages/nuget/index.json --api-key ${PERSONAL_ACCESS_TOKEN}
```

{{< /tab >}}

{{< tab title="Générique" >}}

Téléversez des paquets génériques :

```yaml
upload-package:
  script:
    - 'curl --header "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file my-package.zip "${CI_API_V4_URL}/projects/GENERIC_PACKAGES_PROJECT_ID/packages/generic/my-package/1.0.0/my-package.zip"'
```

{{< /tab >}}

{{< /tabs >}}

## Consommer des paquets {#consume-packages}

Pour la consommation de paquets, vous pouvez :

- Utiliser le registre virtuel Maven.
- Utiliser le point de terminaison du groupe principal.

### Utilisation du registre virtuel Maven (version bêta) {#using-the-maven-virtual-registry-beta}

Le registre virtuel Maven peut améliorer votre configuration de gestion des artefacts en agrégeant des paquets provenant de plusieurs sources. Vous pouvez :

- Ajoutez des paquets internes en utilisant le point de terminaison de votre groupe principal pour Maven comme source amont. Par exemple, `https://gitlab.example.com/api/v4/groups/artifact-management/-/packages/maven`.
- Ajoutez des registres sources amont externes, tels que Maven Central ou des registres privés.
- Ajoutez d'autres projets ou groupes GitLab.

Cette approche fournit un point de terminaison unique qui combine les dépendances internes et externes avec une mise en cache intelligente et une priorisation des sources amont.

Utilisez le registre virtuel Maven lorsque vous :

- Devez agréger des paquets GitLab internes avec des registres sources amont externes
- Souhaitez mettre en cache des dépendances externes pour améliorer la fiabilité
- Devez prioriser les registres privés par rapport aux registres publics
- Souhaitez un point de terminaison unique qui gère à la fois les dépendances internes et externes

La publication n'est pas prise en charge par le registre virtuel Maven.

Pour plus d'informations, voir [Registre virtuel Maven](../virtual_registry/maven/_index.md).

#### Configurer le registre virtuel Maven dans un groupe principal de gestion des artefacts {#configure-the-maven-virtual-registry-within-a-top-level-artifact-management-group}

1. Créez le registre virtuel au niveau du groupe principal :
   - Dans votre groupe `artifact-management`, accédez à **Déployer** > **Registre virtuel**.
   - Créez un registre virtuel Maven (par exemple, « Company Maven Registry »).
1. Configurez les registres sources amont :
   - Ajoutez votre projet `java-packages` interne comme source amont.
   - Ajoutez des registres externes tels que Maven Central ou des dépôts privés.
   - Ordonnez les sources amont en plaçant les registres privés en premier et les registres publics en dernier.
1. Configurez les clients Maven pour utiliser le registre virtuel :

```xml
   <mirrors>
     <mirror>
       <id>central-proxy</id>
       <name>GitLab virtual registry</name>
       <url>https://gitlab.example.com/api/v4/virtual_registries/packages/maven/<registry_id></url>
       <mirrorOf>central</mirrorOf>
     </mirror>
   </mirrors>
```

Le registre virtuel prend en charge plusieurs types de jetons, notamment les jetons d'accès personnels, les jetons de déploiement de groupe, les jetons d'accès de groupe et les jetons de job CI/CD. Chaque type de jeton utilise un nom d'en-tête HTTP différent. Pour plus d'informations, voir [S'authentifier auprès du registre virtuel](../virtual_registry/_index.md#authenticate-to-the-virtual-registry).

L'exemple suivant met en œuvre un jeton d'accès personnel :

```xml
   <servers>
     <server>
       <id>gitlab-maven</id>
       <configuration>
         <httpHeaders>
           <property>
             <name>Private-Token</name>
             <value>${PERSONAL_ACCESS_TOKEN}</value>
           </property>
         </httpHeaders>
       </configuration>
     </server>
   </servers>
```

### Configurer un point de terminaison de groupe principal {#configure-a-top-level-group-endpoint}

Configurez vos projets pour consommer des paquets depuis le point de terminaison du groupe principal. Cette approche donne accès à tous les types de paquets via une configuration unique :

{{< tabs >}}

{{< tab title="Maven" >}}

Configurez votre `pom.xml` pour consommer depuis le registre du groupe :

```xml
<repositories>
    <repository>
        <id>gitlab-maven</id>
        <url>https://gitlab.example.com/api/v4/groups/artifact-management/-/packages/maven</url>
    </repository>
</repositories>
```

Configurez l'authentification dans votre `settings.xml` :

```xml
<settings>
    <servers>
        <server>
            <id>gitlab-maven</id>
            <username>deploy-token-username</username>
            <password>deploy-token-password</password>
        </server>
    </servers>
</settings>
```

{{< /tab >}}

{{< tab title="npm" >}}

Configurez votre fichier `.npmrc` :

```ini
@company:registry=https://gitlab.example.com/api/v4/groups/artifact-management/-/packages/npm/
//gitlab.example.com/api/v4/groups/artifact-management/-/packages/npm/:_authToken=${DEPLOY_TOKEN}
```

{{< /tab >}}

{{< tab title="PyPI" >}}

Configurez `pip` pour utiliser le registre du groupe :

```ini
# pip.conf or ~/.pip/pip.conf
[global]
extra-index-url = https://deploy-token-username:deploy-token-password@gitlab.example.com/api/v4/groups/artifact-management/-/packages/pypi/simple/
```

Ou utilisez des variables d'environnement :

```shell
pip install --index-url https://deploy-token-username:deploy-token-password@gitlab.example.com/api/v4/groups/artifact-management/-/packages/pypi/simple/ --no-index my-package
```

{{< /tab >}}

{{< tab title="Registre de conteneurs" >}}

Extrayez des images depuis le registre du groupe :

```shell
docker login gitlab.example.com -u deploy-token-username -p deploy-token-password
docker pull gitlab.example.com/artifact-management/docker-images/my-app:latest
```

{{< /tab >}}

{{< tab title="Terraform" >}}

Configurez Terraform pour utiliser les informations d'identification GitLab avec des variables d'environnement :

```shell
export TF_TOKEN_gitlab_example_com="deploy-token-password"
```

Référencez ensuite les modules dans votre configuration Terraform :

```hcl
module "example" {
  source = "gitlab.example.com/artifact-management/terraform-modules//my-module"
  version = "1.0.0"
}
```

Ou en utilisant l'URL spécifique au projet :

```hcl
module "example" {
  source = "https://gitlab.example.com/api/v4/projects/TERRAFORM_PACKAGES_PROJECT_ID/packages/terraform/modules/my-module/my-provider/1.0.0"
}
```

{{< /tab >}}

{{< tab title="NuGet" >}}

Configurez NuGet pour utiliser le registre du groupe :

```xml
<!-- nuget.config -->
<configuration>
  <packageSources>
    <add key="GitLab" value="https://gitlab.example.com/api/v4/groups/artifact-management/-/packages/nuget/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <GitLab>
      <add key="Username" value="deploy-token-username" />
      <add key="ClearTextPassword" value="deploy-token-password" />
    </GitLab>
  </packageSourceCredentials>
</configuration>
```

{{< /tab >}}

{{< tab title="Générique" >}}

Téléchargez des paquets génériques :

```shell
curl --header "DEPLOY-TOKEN: ${DEPLOY_TOKEN}" "https://gitlab.example.com/api/v4/groups/artifact-management/-/packages/generic/my-package/1.0.0/my-package.zip" --output my-package.zip
```

{{< /tab >}}

{{< /tabs >}}

## Exemple de configuration CI/CD {#example-cicd-configuration}

L'exemple suivant vous montre comment un projet peut consommer des paquets de plusieurs types :

```yaml
stages:
  - build
  - test

variables:
  MAVEN_OPTS: "-Dmaven.repo.local=${CI_PROJECT_DIR}/.m2/repository"

before_script:
  # Configure npm registry
  - echo "@company:registry=${CI_API_V4_URL}/groups/artifact-management/-/packages/npm/" >> .npmrc
  - echo "//${CI_SERVER_HOST}/api/v4/groups/artifact-management/-/packages/npm/:_authToken=${CI_JOB_TOKEN}" >> .npmrc

build:
  stage: build
  script:
    # Install npm dependencies from group registry
    - npm install
    # Build with Maven dependencies from group registry
    - mvn compile
  cache:
    paths:
      - .m2/repository/
      - node_modules/
```

## Publier aux côtés du code source {#publish-alongside-source-code}

Certaines organisations préfèrent publier des paquets aux côtés du code source de leur application, comme décrit dans le [tutoriel à l'échelle de l'entreprise](../package_registry/enterprise_structure_tutorial.md). Cette approche fonctionne bien lorsque :

- Les paquets sont étroitement liés à des applications spécifiques.
- Vous souhaitez que la propriété des paquets soit alignée sur la propriété du code source.
- Les équipes gèrent à la fois le code et les paquets ensemble.

L'approche de gestion des artefacts fonctionne mieux lorsque :

- Vous souhaitez une gouvernance rationalisée des paquets.
- Les paquets sont partagés entre plusieurs projets.
- Vous avez besoin de politiques et de contrôles spécifiques à chaque type.
- Vous migrez depuis des dépôts d'artefacts traditionnels.

Commencez par les types de paquets les plus utilisés par votre organisation, puis développez la structure au fur et à mesure que vous adoptez des formats de paquets supplémentaires. Cette approche s'adapte naturellement tout en maintenant la sécurité et la facilité d'utilisation.
