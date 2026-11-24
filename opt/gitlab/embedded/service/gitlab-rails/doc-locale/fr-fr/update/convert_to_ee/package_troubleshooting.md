---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Résolution des problèmes de conversion de CE vers EE
---

Lors de la conversion d'une installation de package Linux de GitLab Community Edition vers GitLab Enterprise Edition, vous pouvez rencontrer les problèmes suivants.

## Erreur RPM « package is already installed » {#rpm-package-is-already-installed-error}

Si vous utilisez RPM, vous pouvez obtenir une erreur similaire à :

```shell
package gitlab-7.5.2_omnibus.5.2.1.ci-1.el7.x86_64 (which is newer than gitlab-7.5.2_ee.omnibus.5.2.1.ci-1.el7.x86_64) is already installed
```

Vous pouvez ignorer cette vérification de version avec l'option `--oldpackage` :

```shell
sudo rpm -Uvh --oldpackage gitlab-7.5.2_ee.omnibus.5.2.1.ci-1.el7.x86_64.rpm
```

## Package rendu obsolète par un package installé {#package-obsoleted-by-installed-package}

Les packages Community Edition (CE) et Enterprise Edition (EE) sont marqués comme s'excluant mutuellement afin que les deux ne soient pas installés simultanément.

Si vous utilisez des fichiers RPM locaux pour passer de CE à EE ou inversement, utilisez `rpm` pour installer le package plutôt que `yum`. Si vous essayez d'utiliser yum, vous pouvez obtenir une erreur de ce type :

```plaintext
Cannot install package gitlab-ee-11.8.3-ee.0.el6.x86_64. It is obsoleted by installed package gitlab-ce-11.8.3-ce.0.el6.x86_64
```

Pour éviter ce problème, vous pouvez soit :

- Suivre les mêmes instructions fournies dans la section [Mettre à niveau avec un package téléchargé](../package/_index.md#upgrade-with-a-downloaded-package).
- Désactiver temporairement cette vérification dans yum en ajoutant `--setopt=obsoletes=0` aux options transmises à la commande.

## Erreur 500 lors de l'accès aux paramètres du dépôt du projet {#500-error-when-accessing-project-repository-settings}

Cette erreur survient lorsque GitLab est converti de Community Edition (CE) vers Enterprise Edition (EE), puis repassé en CE, puis à nouveau en EE.

Lors de la consultation des paramètres du dépôt d'un projet, vous pouvez voir cette erreur dans les journaux :

```shell
Processing by Projects::Settings::RepositoryController#show as HTML
  Parameters: {"namespace_id"=>"<namespace_id>", "project_id"=>"<project_id>"}
Completed 500 Internal Server Error in 62ms (ActiveRecord: 4.7ms | Elasticsearch: 0.0ms | Allocations: 14583)

NoMethodError (undefined method `commit_message_negative_regex' for #<PushRule:0x00007fbddf4229b8>
Did you mean?  commit_message_regex_change):
```

Cette erreur est causée par l'ajout d'une fonctionnalité EE à une instance CE lors du passage initial vers EE. Une fois l'instance repassée en CE puis mise à niveau à nouveau vers EE, la table `push_rules` existe déjà dans la base de données. Par conséquent, une migration est incapable d'ajouter la colonne `commit_message_regex_change`.

Cela entraîne un dysfonctionnement de la [migration de backport des tables EE](https://gitlab.com/gitlab-org/gitlab/-/blob/cf00e431024018ddd82158f8a9210f113d0f4dbc/db/migrate/20190402150158_backport_enterprise_schema.rb#L1619). La migration de backport suppose que certaines tables de la base de données n'existent pas lors de l'exécution en CE.

Pour résoudre ce problème :

1. Démarrez une console de base de données :

   ```shell
   sudo gitlab-rails dbconsole --database main
   ```

1. Ajoutez manuellement la colonne `commit_message_negative_regex` manquante :

   ```sql
   ALTER TABLE push_rules ADD COLUMN commit_message_negative_regex VARCHAR;

   # Exit psql
   \q
   ```

1. Redémarrez GitLab :

   ```shell
   sudo gitlab-ctl restart
   ```
