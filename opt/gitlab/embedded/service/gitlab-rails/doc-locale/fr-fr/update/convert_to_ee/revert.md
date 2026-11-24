---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Revenir de l'Enterprise Edition à la Community Edition"
---

Vous pouvez faire revenir votre instance Enterprise Edition (EE) à la Community Edition (CE), mais vous devez d'abord :

1. Désactiver les mécanismes d'authentification exclusifs à EE.
1. Supprimer les intégrations exclusives à EE de la base de données.
1. Ajuster la configuration qui utilise des portées d'environnement.

## Désactiver les mécanismes d'authentification exclusifs à EE {#turn-off-ee-only-authentication-mechanisms}

Kerberos est uniquement disponible sur les instances EE. Vous devez :

- Désactiver ces mécanismes avant de revenir à la version précédente.
- Fournir une autre méthode d'authentification à vos utilisateurs.

## Supprimer les intégrations exclusives à EE de la base de données {#remove-ee-only-integrations-from-the-database}

Ces intégrations sont uniquement disponibles dans la base de code EE :

- [GitHub](../../user/project/integrations/github.md)
- [Git Guardian](../../user/project/integrations/git_guardian.md)
- [Google Artifact Management](../../user/project/integrations/google_artifact_management.md)
- [Google Cloud IAM](../../integration/google_cloud_iam.md)

Si vous effectuez une rétrogradation vers CE, vous pourriez obtenir une erreur similaire à la suivante :

```plaintext
Completed 500 Internal Server Error in 497ms (ActiveRecord: 32.2ms)

ActionView::Template::Error (The single-table inheritance mechanism failed to locate the subclass: 'Integrations::Github'. This
error is raised because the column 'type_new' is reserved for storing the class in case of inheritance. Please rename this
column if you didn't intend it to be used for storing the inheritance class or overwrite Integration.inheritance_column to
use another column for that information.)
```

Le `subclass` dans le message d'erreur peut être l'un des éléments suivants :

- `Integrations::Github`
- `Integrations::GitGuardian`
- `Integrations::GoogleCloudPlatform::ArtifactRegistry`
- `Integrations::GoogleCloudPlatform::WorkloadIdentityFederation`

Toutes les intégrations sont créées automatiquement pour chaque projet que vous possédez. Pour éviter cette erreur, vous devez supprimer tous les enregistrements d'intégrations exclusives à EE de votre base de données.

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

```shell
sudo gitlab-rails runner "Integration.where(type_new: ['Integrations::Github']).delete_all"
sudo gitlab-rails runner "Integration.where(type_new: ['Integrations::GitGuardian']).delete_all"
sudo gitlab-rails runner "Integration.where(type_new: ['Integrations::GoogleCloudPlatform::ArtifactRegistry']).delete_all"
sudo gitlab-rails runner "Integration.where(type_new: ['Integrations::GoogleCloudPlatform::WorkloadIdentityFederation']).delete_all"
```

{{< /tab >}}

{{< tab title="Auto-compilée (source)" >}}

```shell
bundle exec rails runner "Integration.where(type_new: ['Integrations::Github']).delete_all" production
bundle exec rails runner "Integration.where(type_new: ['Integrations::GitGuardian']).delete_all" production
bundle exec rails runner "Integration.where(type_new: ['Integrations::GoogleCloudPlatform::ArtifactRegistry']).delete_all" production
bundle exec rails runner "Integration.where(type_new: ['Integrations::GoogleCloudPlatform::WorkloadIdentityFederation']).delete_all" production
```

{{< /tab >}}

{{< /tabs >}}

## Ajuster la configuration qui utilise des portées d'environnement {#adjust-configuration-that-uses-environment-scopes}

Si vous utilisez des [portées d'environnement](../../user/group/clusters/_index.md#environment-scopes), vous devrez peut-être ajuster votre configuration, notamment si des variables de configuration partagent la même clé mais ont des portées différentes. Les portées d'environnement sont complètement ignorées dans CE.

Avec des variables de configuration qui partagent une clé mais des portées différentes, vous pourriez accidentellement obtenir une variable que vous n'attendez pas pour un environnement particulier. Assurez-vous d'avoir les bonnes variables dans ce cas.

Vos données sont entièrement préservées lors de la transition, vous pouvez donc revenir à EE et restaurer le comportement.

## Revenir à CE {#revert-to-ce}

Après avoir effectué les étapes nécessaires, vous pouvez faire revenir votre instance GitLab à CE.

Suivez les [guides de mise à jour](../_index.md) appropriés pour vous assurer que toutes les dépendances sont à jour.

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

Installez le paquet Community Edition en suivant les [instructions d'installation pour votre distribution](../../install/package/_index.md#supported-platforms).

{{< /tab >}}

{{< tab title="Auto-compilée (source)" >}}

1. Remplacez le remote Git actuel de votre installation GitLab par le remote Git CE.
1. Récupérez les dernières modifications et basculez sur la dernière branche stable. Par exemple :

   ```shell
   git remote set-url origin git@gitlab.com:gitlab-org/gitlab-foss.git
   git fetch --all
   git checkout 17-8-stable
   ```

{{< /tab >}}

{{< /tabs >}}

## Dépannage {#troubleshooting}

Cette section contient les solutions possibles aux problèmes que vous pourriez rencontrer.

### Erreur : `Cookbook gitlab-ee not found` {#error-cookbook-gitlab-ee-not-found}

Vous pourriez rencontrer l'erreur `Cookbook gitlab-ee not found` lors de l'installation du paquet Linux pour GitLab CE sur une instance GitLab EE. Pour résoudre ce problème :

1. Supprimez le cookbook `gitlab-ee` :

   ```shell
   sudo rm -rf /opt/gitlab/embedded/cookbooks/cache/cookbooks/gitlab-ee
   ```

1. Réinstallez GitLab CE.
1. Vérifiez que tous les services sont opérationnels :

   ```shell
   sudo gitlab-ctl status
   ```

   Si ce n'est pas le cas, redémarrez GitLab :

   ```shell
   sudo gitlab-ctl restart
   ```
