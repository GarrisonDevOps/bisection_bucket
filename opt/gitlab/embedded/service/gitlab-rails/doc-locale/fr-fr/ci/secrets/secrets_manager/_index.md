---
stage: Security Platform
group: Secrets Manager Application
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: GitLab Secrets Manager
ignore_in_report: true
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/epics/16319) dans GitLab 18.3 [avec les feature flags](../../../development/feature_flags/_index.md) `secrets_manager` et `ci_tanukey_ui`. Désactivé par défaut.
- Feature flag `ci_tanukey_ui` [supprimé](https://gitlab.com/gitlab-org/gitlab/-/issues/549940) dans GitLab 18.4.
- Rendu disponible pour certains utilisateurs en version bêta fermée dans GitLab 18.8.
- Le gestionnaire de secrets de groupe [introduit](https://gitlab.com/groups/gitlab-org/-/work_items/17904) et rendu disponible aux utilisateurs de la version bêta fermée dans la version 18.10 [avec le feature flag](../../../development/feature_flags/_index.md) `group_secrets_manager`.
- [Passage](https://gitlab.com/groups/gitlab-org/-/work_items/21731) de la version bêta fermée à la version bêta publique dans GitLab 19.0.
- [Passage](https://gitlab.com/groups/gitlab-org/-/work_items/10723) en disponibilité limitée sur GitLab.com dans GitLab 19.3.
- Les permissions de lecture et d'écriture par défaut pour le rôle Maintainer dans les projets ont été [introduites](https://gitlab.com/gitlab-org/gitlab/-/work_items/623437) dans GitLab 19.4.
- Les permissions de lecture des métadonnées et de création par défaut pour le rôle Developer dans les projets ont été [introduites](https://gitlab.com/gitlab-org/gitlab/-/work_items/623438) dans GitLab 19.5.
- Les permissions de secrets pour les groupes ont été [supprimées](https://gitlab.com/gitlab-org/gitlab/-/work_items/623457) dans GitLab 19.4. Les permissions de groupe n'accordent plus d'accès, et le type de principal `GROUP`, l'argument `groupPath` de `PrincipalInput`, ainsi que le champ `group` de `Principal` ont été supprimés de l'API GraphQL. Accordez plutôt les permissions aux utilisateurs ou aux rôles.
- Les feature flags `secrets_manager` et `group_secrets_manager` ont été [supprimés](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259222) dans GitLab 19.5.
- [Généralement disponible](https://gitlab.com/groups/gitlab-org/-/work_items/17903) dans GitLab 19.5.

{{< /history >}}

Utilisez GitLab Secrets Manager pour chiffrer, stocker et récupérer des identifiants de manière sécurisée pour vos projets et groupes, propulsé par [OpenBao](https://openbao.org/). Plutôt que de coder en dur des identifiants ou de vous fier aux variables CI/CD, vous pouvez récupérer des secrets avec une [auditabilité complète](../../../user/compliance/audit_event_types.md#secrets-management) en utilisant le modèle d'accès GitLab et le système d'audit.

Les secrets représentent des informations sensibles dont vos jobs CI/CD ont besoin pour fonctionner, tels que des jetons d'accès, des identifiants de base de données ou des clés privées. Contrairement aux variables CI/CD, qui sont toujours disponibles par défaut pour les jobs, les secrets doivent être explicitement demandés par un job.

Vous pouvez [utiliser des secrets dans les jobs CI/CD](#use-secrets-in-job-scripts) ou [en dehors de CI/CD pour des charges de travail en temps réel](non_cicd_access.md), comme Kubernetes, Terraform, ou via l'API.

GitLab Secrets Manager [consomme des GitLab Credits](credit_usage.md).

Partagez vos commentaires dans le [ticket 598100](https://gitlab.com/gitlab-org/gitlab/-/work_items/598100).

## Activer GitLab Secrets Manager {#enable-gitlab-secrets-manager}

Sur GitLab.com, vous activez GitLab Secrets Manager pour un groupe principal. Tous les sous-groupes et projets de ce groupe peuvent ensuite utiliser le Gestionnaire de secrets.

Sur GitLab Self-Managed, un administrateur active le Gestionnaire de secrets pour l'instance. Tous les groupes et projets de l'instance peuvent ensuite utiliser le Gestionnaire de secrets.

Une fois le Gestionnaire de secrets activé, vous pouvez [créer des secrets](#define-a-secret) dans n'importe lequel de ces groupes et projets.

### Pour GitLab.com {#for-gitlabcom}

#### Activer avec GitLab Credits {#enable-with-gitlab-credits}

{{< history >}}

- L'option **Activer avec GitLab Credits** a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254349) dans GitLab 19.4.

{{< /history >}}

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe principal.

Pour activer GitLab Secrets Manager avec GitLab Credits :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Gestionnaire de secrets**.
1. Sélectionnez **Activer avec GitLab Credits**.
1. Dans la boîte de dialogue de confirmation, sélectionnez **Gestionnaire de secrets GitLab**.

Si votre abonnement ne dispose d'aucun GitLab Credits, le propriétaire de l'abonnement doit d'abord souscrire un engagement mensuel ou accepter la facturation à la demande dans le portail clients.

#### Démarrer un essai {#start-a-trial}

Vous pouvez également [démarrer un essai de 30 jours](credit_usage.md#on-gitlabcom) pour essayer GitLab Secrets Manager avec des crédits d'évaluation temporaires. Une fois l'essai expiré, GitLab Secrets Manager commence à consommer des GitLab Credits. Pour éviter une interruption de service, souscrivez un engagement mensuel de crédits ou acceptez les conditions de facturation à l'utilisation avant la fin de l'essai.

### Pour GitLab Self-Managed {#for-gitlab-self-managed}

Seul un administrateur peut activer ou désactiver le Gestionnaire de secrets, et le paramètre s'applique à l'ensemble de l'instance. Tant que le Gestionnaire de secrets n'est pas activé, l'élément **Gestionnaire de secrets** n'apparaît pas dans la barre latérale gauche.

Lorsque vous activez GitLab Secrets Manager pour l'instance, tous les groupes et projets de l'instance peuvent utiliser le Gestionnaire de secrets.

Prérequis :

- Disposer d'un accès administrateur.
- OpenBao doit être [installé et configuré](../../../administration/secrets_manager/_index.md#install-openbao).
- Vous devez disposer d'un abonnement Premium ou Ultimate.

Avec une licence en ligne, vous pouvez démarrer un essai ou activer avec GitLab Credits. Si votre instance utilise une licence hors ligne, consultez [activer avec une licence hors ligne](#enable-with-an-offline-license).

#### Démarrer un essai {#start-a-trial-1}

Pour plus d'informations sur les crédits d'essai, la date de fin de l'essai et les étapes pour démarrer un essai, consultez [démarrer un essai sur GitLab Self-Managed](credit_usage.md#on-gitlab-self-managed).

#### Activer avec GitLab Credits {#enable-with-gitlab-credits-1}

Prérequis :

- Votre instance doit disposer d'une licence cloud en ligne.
- Votre abonnement doit disposer de GitLab Credits, via un engagement mensuel ou une facturation à la demande acceptée dans le portail clients.

Pour activer GitLab Secrets Manager avec GitLab Credits :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**.
1. Développez **GitLab Secrets Manager**.
1. Sélectionnez **Activer avec GitLab Credits**.
1. Dans la boîte de dialogue de confirmation, sélectionnez **Gestionnaire de secrets GitLab**.

#### Activer avec une licence hors ligne {#enable-with-an-offline-license}

Les instances hors ligne ne peuvent pas démarrer un essai ni utiliser **Activer avec GitLab Credits**. Activez plutôt le bouton bascule **Gestionnaire de secrets**.

Votre licence hors ligne doit inclure GitLab Secrets Manager.

Pour activer GitLab Secrets Manager :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**.
1. Développez **GitLab Secrets Manager**.
1. Activez le bouton **Secrets Manager**.

Si votre licence n'inclut pas GitLab Secrets Manager, le bouton bascule est désactivé et la section affiche une alerte. Contactez le propriétaire de l'abonnement pour acheter une licence.

## Définir un secret {#define-a-secret}

Vous pouvez ajouter des secrets à GitLab Secrets Manager afin qu'il puisse être utilisé pour des pipelines CI/CD et des workflows sécurisés.

Les secrets définis pour un projet ne sont accessibles que par les pipelines du même projet. Les secrets définis pour un groupe ne sont accessibles que par les pipelines d'un projet directement sous le groupe ou dans sa hiérarchie de sous-groupes.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Sélectionnez **Sécurisation** > **Secrets Manager**.
1. Sélectionnez **Nouveau secret** et renseignez les détails :
   - **Nom** : doit être unique dans le projet ou le groupe où il est créé, comporter 255 caractères ou moins, et ne contenir que des lettres, des chiffres et des tirets bas (`_`). Vous ne pouvez pas modifier le nom après avoir créé le secret.
   - **Valeur** : doit être inférieure ou égale à 10 Ko (10 000 octets).
   - **Description** : maximum de 200 caractères.
   - **Environnements** : Peut être :
     - **Tous (par défaut)** (`*`)
     - Un [environnement](../../environments/_index.md#types-of-environments) spécifique.
     - Un [environnement avec caractères génériques](../../environments/_index.md#limit-the-environment-scope-of-a-cicd-variable).
   - **Branches** : cette option n'existe que dans les paramètres du projet. Peut être :
     - Une branche spécifique.
     - Une branche avec caractères génériques (doit contenir le caractère `*`).
   - **Branches protégées** : cette option n'existe que dans les paramètres du groupe. facultatif. Exporter les secrets vers les pipelines s'exécutant uniquement sur des branches protégées.
   - **Période de rappel de modification** : facultatif. Envoyer un rappel par e-mail pour effectuer la rotation du secret après le nombre de jours défini. Minimum 7 jours.
1. Sélectionnez **Ajouter un secret**.

[Par défaut](../../../administration/instance_limits.md#secrets-manager-limits), vous pouvez stocker un maximum de 100 secrets par projet et 500 par groupe. Les secrets d'un sous-groupe ou d'un projet membre ne sont pas comptabilisés dans la limite du groupe parent.

Après avoir créé un secret :

- Vous pouvez l'utiliser dans la configuration du pipeline ou dans les scripts de job.
- Si vous modifiez le secret, vous pouvez uniquement écraser la valeur par une nouvelle valeur. Vous ne pouvez pas récupérer la valeur du secret via l'interface utilisateur. Pour plus d'informations, consultez les [permissions pour GitLab Secrets Manager](../../../user/permissions.md#project-secrets-manager).

> [!warning]
> La valeur d'un secret est accessible à tous les jobs de pipeline CI/CD s'exécutant pour l'environnement ou la branche spécifique définis lors de la création ou de la mise à jour du secret. Assurez-vous que seuls les utilisateurs autorisés à accéder à la valeur de ces secrets peuvent exécuter des jobs pour l'environnement ou la branche spécifiés.

## Utiliser les secrets dans les scripts de job {#use-secrets-in-job-scripts}

Par défaut, à l'instar des [variables CI/CD de type fichier](../../variables/_index.md#use-file-type-cicd-variables), un secret est mis à disposition dans un job sous forme de fichier avec une variable d'environnement associée :

- La clé du secret est le nom de la variable d'environnement.
- La valeur du secret est enregistrée dans un fichier temporaire. Contrairement aux variables CI/CD masquées, les secrets peuvent contenir des espaces et des retours à la ligne.
- Le chemin vers le fichier temporaire est la valeur de la variable d'environnement.

Utilisez un secret dans les scripts de job avec des commandes qui acceptent des fichiers en entrée, ou directement en option [utilisez le secret comme variable d'environnement](#use-a-secret-as-an-environment-variable-with-file-false).

Si un job affiche la valeur d'un secret, GitLab remplace la valeur dans le job log par `[MASKED]`.

### Pour les secrets de projet {#for-project-secrets}

Prérequis :

- GitLab Runner 19.0 ou version ultérieure.

Pour accéder aux secrets stockés dans le Gestionnaire de secrets pour un projet, utilisez les mots-clés [`secrets`](../../yaml/_index.md#secrets) et `gitlab_secrets_manager`.

Par exemple :

```yaml
job:
  secrets:
    KUBE_CA_PEM:
      gitlab_secrets_manager:
        name: kube_cert
  script:
   - kubectl config set-cluster e2e --server="https://example.com" --certificate-authority="$KUBE_CA_PEM"
```

### Pour les secrets de groupe {#for-group-secrets}

Prérequis :

- GitLab Runner 19.0 ou version ultérieure.

Pour accéder aux secrets stockés dans le Gestionnaire de secrets pour un groupe :

- Utilisez les mots-clés [`secrets`](../../yaml/_index.md#secrets) et `gitlab_secrets_manager`.
- Spécifiez le groupe comme source du gestionnaire de secrets en utilisant le champ `source` avec le préfixe `group/` suivi de `<full-path-to-group>`. Le groupe doit être le groupe du projet ou l'un de ses groupes parents. Par exemple, un pipeline dans une duplication appartenant à un autre groupe ne peut pas lire le secret.

Par exemple :

```yaml
job:
  secrets:
    KUBE_CA_PEM:
      gitlab_secrets_manager:
        name: kube_cert
        source: group/my-group/my-subgroup
  script:
   - kubectl config set-cluster e2e --server="https://example.com" --certificate-authority="$KUBE_CA_PEM"
```

### Utiliser un secret comme variable d'environnement avec `file: false` {#use-a-secret-as-an-environment-variable-with-file-false}

Pour utiliser un secret comme variable d'environnement sans le stocker dans un fichier, définissez `file: false` pour le secret. Par exemple :

```yaml
job:
  secrets:
    DEPLOY_SECRET:
      gitlab_secrets_manager:
        name: deploy_credentials
      file: false
  script:
    - my_deploy_command --user username --pass $DEPLOY_SECRET
```

Dans cet exemple, le secret est mis à disposition du job en tant que variable `DEPLOY_SECRET`, que vous pouvez utiliser comme n'importe quelle autre variable d'environnement.

## Notifications de rotation du secret {#secret-rotation-notifications}

Les utilisateurs avec le rôle Propriétaire dans le projet reçoivent une notification par e-mail pour effectuer la rotation du secret le jour spécifié dans la configuration du secret.

## Accéder aux secrets depuis des charges de travail non CI/CD {#access-secrets-from-non-cicd-workloads}

Les charges de travail qui ne s'exécutent pas en tant que jobs GitLab CI/CD peuvent lire les secrets via l'API du Gestionnaire de secrets. Pour plus d'informations, consultez [Accéder aux secrets depuis des charges de travail non CI/CD](non_cicd_access.md).

## Gérer les autorisations des secrets {#manage-secrets-permissions}

### Pour un projet {#for-a-project}

{{< history >}}

- La permission d'écriture a été [mise à jour](https://gitlab.com/gitlab-org/gitlab/-/work_items/630995) pour séparer les permissions de création et de mise à jour dans GitLab 19.6.

{{< /history >}}

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le projet afin de gérer les autorisations des secrets.
- Les utilisateurs avec le rôle Chargé de maintenance pour le projet peuvent consulter les autorisations définies.
- GitLab Secrets Manager doit être activé.

Pour mettre à jour les autorisations des secrets pour un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou aller à** et trouvez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**.
1. Développez **Visibilité, fonctionnalités du projet, autorisations**.
1. Sous **Gestionnaire de secrets GitLab**, dans la section **Autorisations de l'utilisateur ou utilisatrice** :
   - Sélectionnez **Ajouter** pour ajouter des règles de permissions pour des utilisateurs ou des rôles spécifiques.
   - Vous pouvez définir des portées de permissions pour lire les métadonnées, lire la valeur, supprimer, créer et mettre à jour des secrets. Pour sélectionner la portée de mise à jour, vous devez également sélectionner la portée de création.
   - facultatif. Définissez une **Date d'expiration de l'accès** pour faire expirer les permissions.

Pour les gestionnaires de secrets activés dans GitLab 19.4 et versions ultérieures, les utilisateurs disposant du rôle Maintainer pour le projet ont par défaut les permissions de lecture des métadonnées, de création et de mise à jour.

Les utilisateurs disposant du rôle Developer pour le projet ont par défaut les permissions de lecture des métadonnées et de création. La permission de création n'inclut pas la mise à jour, de sorte que ces utilisateurs peuvent ajouter des secrets mais ne peuvent pas modifier les secrets déjà existants.

Les utilisateurs disposant du rôle Owner peuvent supprimer ou modifier ces permissions par défaut.

### Pour un groupe {#for-a-group}

{{< history >}}

- Le paramètre du groupe principal a été [déplacé](https://gitlab.com/gitlab-org/gitlab/-/issues/605581) de **Paramètres** > **Général** vers **Paramètres** > **Sécuriser** dans GitLab 19.4
- La permission d'écriture a été [mise à jour](https://gitlab.com/gitlab-org/gitlab/-/work_items/630995) pour séparer les permissions de création et de mise à jour dans GitLab 19.6.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Owner pour le groupe afin de gérer les permissions de secrets. Seuls les utilisateurs avec le rôle Propriétaire pour le groupe peuvent consulter les autorisations définies.
- GitLab Secrets Manager doit être activé.

Pour mettre à jour les autorisations des secrets pour un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou aller à** et trouvez votre groupe.
1. Dans la barre latérale gauche :
   - Dans un groupe principal, sélectionnez **Paramètres** > **Sécuriser**.
   - Dans un sous-groupe, sélectionnez **Paramètres** > **Général** et développez **Permissions et fonctionnalités du groupe**.
1. Sous **Gestionnaire de secrets GitLab**, dans la section **Autorisations de l'utilisateur ou utilisatrice** :
   - Sélectionnez **Ajouter** pour ajouter des règles de permissions pour des utilisateurs ou des rôles spécifiques.
   - Vous pouvez définir des portées de permissions pour lire les métadonnées, lire la valeur, supprimer, créer et mettre à jour des secrets. Pour sélectionner la portée de mise à jour, vous devez également sélectionner la portée de création.
   - facultatif. Définissez une **Date d'expiration de l'accès** pour faire expirer les permissions.

Les utilisateurs avec le rôle Propriétaire pour le groupe ont toujours les autorisations pour effectuer toutes les opérations dans GitLab Secrets Manager.

## Suppression d'un projet ou d'un groupe {#deletion-of-a-project-or-group}

Lorsque vous [supprimez un projet](../../../user/project/working_with_projects.md#delete-a-project) ou [supprimez un groupe](../../../user/group/_index.md#schedule-a-group-for-deletion) avec des secrets :

- GitLab Secrets Manager pour le projet ou le groupe est désactivé et supprimé du moteur de stockage des secrets.
- Tous les secrets sont définitivement supprimés.

## Transfert d'un projet ou d'un groupe {#transfer-of-a-project-or-group}

Lorsque vous [transférez un projet](../../../user/project/working_with_projects.md#transfer-a-project) ou [transférez un groupe](../../../user/group/manage.md#transfer-a-group) avec des secrets :

- Les secrets définis pour le projet ou le groupe ne sont pas transférés vers le projet ou le groupe dans son nouvel espace de nommage.
- GitLab Secrets Manager pour le projet ou le groupe est désactivé et supprimé du moteur de stockage des secrets.
- Tous les secrets sont définitivement supprimés.

## Désactiver GitLab Secrets Manager {#disable-gitlab-secrets-manager}

Lorsque vous désactivez GitLab Secrets Manager :

- Les jobs ou charges de travail qui récupèrent des secrets cessent de fonctionner.
- GitLab ne supprime pas vos secrets.
- Les membres du projet et du groupe peuvent uniquement consulter les détails ou supprimer les secrets existants.
- Le Gestionnaire de secrets ne consomme pas de GitLab Credits.

Si vous avez démarré un essai, vous pouvez réactiver le Gestionnaire de secrets à tout moment avant la fin de l'essai.

### Désactiver sur GitLab.com {#disable-on-gitlabcom}

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe principal.

Pour désactiver GitLab Secrets Manager :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Sécuriser**.
1. Dans la section **Gestionnaire de secrets GitLab**, désactivez le bouton bascule.
1. Dans la boîte de dialogue de confirmation, sélectionnez **Désactiver**.

Pour réactiver le Gestionnaire de secrets, réactivez le bouton bascule.

### Désactiver sur GitLab Self-Managed {#disable-on-gitlab-self-managed}

La désactivation du Gestionnaire de secrets s'applique à tous les groupes et projets de l'instance. Avec une licence hors ligne incluant l'extension, GitLab cesse de facturer le Gestionnaire de secrets.

Prérequis :

- Disposer d'un accès administrateur.

Pour désactiver GitLab Secrets Manager :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**.
1. Développez **GitLab Secrets Manager**.
1. Désactivez le bouton bascule **Gestionnaire de secrets**.
1. Dans la boîte de dialogue de confirmation, sélectionnez **Désactiver**.

## Sujets connexes {#related-topics}

- [Utilisation des crédits par GitLab Secrets Manager](credit_usage.md)
- [Secret Audit Tool for Variables](https://gitlab.com/guided-explorations/secrets-management/secret-audit-tool-for-variables) : un outil communautaire qui analyse une hiérarchie de groupes GitLab à la recherche de variables CI/CD dont les noms suggèrent qu'elles peuvent contenir des identifiants (mots de passe, jetons, clés API et éléments similaires). Il génère un rapport HTML pour vous aider à identifier les variables à migrer vers GitLab Secrets Manager.

## Dépannage {#troubleshooting}

### Erreur : `reading from Vault: api error: status code 403` {#error-reading-from-vault-api-error-status-code-403}

Lorsqu'un job de pipeline CI/CD tente de récupérer un secret, il peut renvoyer cette erreur :

```plaintext
ERROR: Job failed (system failure): resolving secrets: getting secret: get secret data: reading from Vault: api error: status code 403: 1 error occurred: * permission denied
```

Cette erreur se produit lorsqu'un job tente de récupérer un secret qui n'existe pas ou qui a été supprimé.

### Erreur : `inline auth JWT is required` {#error-inline-auth-jwt-is-required}

Lorsqu'un job de pipeline CI/CD tente de récupérer un secret, il peut renvoyer cette erreur :

```plaintext
ERROR: Job failed (system failure): resolving secrets: creating vault client: configuring inline auth: inline auth JWT is required
```

Cette erreur se produit lorsque l'instance de GitLab Secrets Manager n'a pas encore été provisionnée pour le projet ou le groupe auquel le secret est censé appartenir. Le runner ne peut pas configurer l'authentification car aucun rôle de GitLab Secrets Manager n'existe encore.

Pour résoudre cette erreur, créez un secret dans le projet ou le groupe. Relancez ensuite le pipeline.

### Erreur : `namespace does not have access to GitLab Secrets Manager` {#error-namespace-does-not-have-access-to-gitlab-secrets-manager}

Les jobs qui demandent des secrets à GitLab Secrets Manager échouent avec cette erreur avant qu'un runner ne les prenne en charge lorsque l'espace de nommage n'a pas accès à GitLab Secrets Manager.

#### GitLab.com {#gitlabcom}

Causes possibles sur GitLab.com :

- L'essai a expiré.
- Le groupe ne dispose d'aucun GitLab Credits.
- La facturation à la demande est désactivée.
- La période de grâce de l'abonnement a expiré.
- La version bêta ouverte a pris fin et l'espace de nommage n'a pas participé.

Pour restaurer l'accès au groupe principal, démarrez un essai gratuit ou [activez GitLab Secrets Manager avec GitLab Credits](#enable-with-gitlab-credits). L'abonnement doit disposer de GitLab Credits via un engagement mensuel ou une facturation à la demande. Si l'abonnement a expiré, renouvelez-le. Pour plus d'informations, consultez [Utilisation et facturation de GitLab Secrets Manager](secrets_manager_billing.md).

#### GitLab Self-Managed {#gitlab-self-managed}

Sur GitLab Self-Managed, GitLab résout l'accès au Gestionnaire de secrets au niveau de l'instance, et non par groupe.

Causes possibles :

- L'instance utilise une licence d'essai. Les essais du Gestionnaire de secrets ne sont disponibles qu'avec un abonnement payant.
- L'essai du Gestionnaire de secrets a expiré.
- L'abonnement de l'instance n'inclut pas GitLab Secrets Manager.
- La période de grâce de l'abonnement a expiré.
- Pour les licences hors ligne, la licence n'inclut pas d'extension GitLab Secrets Manager active.

Pour restaurer l'accès, demandez à un administrateur d'instance d'ajouter GitLab Secrets Manager à l'abonnement de l'instance. Les instances disposant d'un abonnement payant peuvent également démarrer un essai gratuit.

### Erreur : `secret source group is not accessible from this project` {#error-secret-source-group-is-not-accessible-from-this-project}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/633509) dans GitLab 19.6 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `secrets_manager_defer_group_source_check`. Désactivé par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Un job échoue avec cette erreur avant son exécution lorsqu'un secret utilise `source: group/<full-path-to-group>` et que ce groupe n'est pas le groupe du projet ou l'un de ses groupes parents. Par exemple, cela se produit dans un pipeline pour une merge request issue d'une duplication, car le pipeline s'exécute dans le projet dupliqué.

GitLab crée tout de même le pipeline. Seuls les jobs utilisant le secret échouent. Les autres jobs du pipeline s'exécutent normalement.

Lorsque le feature flag est désactivé, GitLab ne crée pas les jobs. À la place, le pipeline échoue avec une erreur de ce type :

```plaintext
jobs:<job-name>:secrets:<variable-name>:gitlab_secrets_manager source group with path '<full-path-to-group>' not found
```

Pour résoudre cette erreur, effectuez l'une des opérations suivantes :

- Remplacez `source` par le groupe du projet ou l'un de ses groupes parents.
- Utilisez [`rules`](../../yaml/_index.md#rules) pour exécuter le job uniquement dans les projets qui peuvent lire le secret. Par exemple, si `source` est le groupe principal `group/my-group`, utilisez `if: $CI_PROJECT_ROOT_NAMESPACE == "my-group"`. Cela ne fonctionne que lorsque le feature flag est activé. Lorsqu'il est désactivé, GitLab vérifie la source avant d'évaluer `rules`, de sorte que le pipeline échoue tout de même.
