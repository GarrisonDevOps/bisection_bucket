---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Mise à niveau de PostgreSQL pour Auto DevOps
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lorsque `POSTGRES_ENABLED` est `true`, Auto DevOps fournit une [base de données PostgreSQL dans le cluster](customize.md#postgresql-database-support) pour votre application.

La version du chart utilisée pour provisionner PostgreSQL :

- Peut être définie de 0.7.1 à 8.2.1.

GitLab encourage les utilisateurs à migrer leur base de données vers le chart PostgreSQL plus récent.

Ce guide fournit des instructions sur la façon de migrer votre base de données PostgreSQL, ce qui implique :

1. Effectuer un dump de votre base de données.
1. Installer une nouvelle base de données PostgreSQL en utilisant la version plus récente 8.2.1 du chart et supprimer l'ancienne installation PostgreSQL.
1. Restaurer le dump de base de données dans le nouveau PostgreSQL.

## Prérequis {#prerequisites}

1. Installez [`kubectl`](https://kubernetes.io/docs/tasks/tools/).
1. Assurez-vous de pouvoir accéder à votre cluster Kubernetes en utilisant `kubectl`. Cela varie selon les fournisseurs Kubernetes.
1. Préparez-vous à une interruption de service. Les étapes ci-dessous incluent la mise hors ligne de l'application afin que la base de données dans le cluster ne soit pas modifiée après la création du dump de base de données.
1. Assurez-vous de ne pas avoir défini `POSTGRES_ENABLED` sur `false`, car ce paramètre supprime toute base de données existante du canal 1.

> [!note]
> Si vous avez configuré Auto DevOps avec un environnement de staging, envisagez d'essayer d'abord les étapes de sauvegarde et de restauration sur le staging, ou de tester cela sur un environnement éphémère.

## Mettre votre application hors ligne {#take-your-application-offline}

Si nécessaire, mettez votre application hors ligne pour empêcher la modification de la base de données après la création du dump de base de données.

1. Obtenez l'espace de nommage Kubernetes pour l'environnement. Il ressemble généralement à `<project-name>-<project-id>-<environment>`. Dans cet exemple, l'espace de nommage s'appelle `minimal-ruby-app-4349298-production`.

   ```shell
   $ kubectl get ns

   NAME                                                  STATUS   AGE
   minimal-ruby-app-4349298-production                   Active   7d14h
   ```

1. Pour plus de commodité, exportez le nom de l'espace de nommage :

   ```shell
   export APP_NAMESPACE=minimal-ruby-app-4349298-production
   ```

1. Obtenez le nom du déploiement pour votre application avec la commande suivante. Dans cet exemple, le nom du déploiement est `production`.

   ```shell
   $ kubectl get deployment --namespace "$APP_NAMESPACE"
   NAME                  READY   UP-TO-DATE   AVAILABLE   AGE
   production            2/2     2            2           7d21h
   production-postgres   1/1     1            1           7d21h
   ```

1. Pour empêcher la modification de la base de données, définissez le nombre de réplicas à 0 pour le déploiement avec la commande suivante. Nous utilisons le nom de déploiement de l'étape précédente (`deployments/<DEPLOYMENT_NAME>`).

   ```shell
   $ kubectl scale --replicas=0 deployments/production --namespace "$APP_NAMESPACE"
   deployment.extensions/production scaled
   ```

1. Vous devez également définir le nombre de réplicas à zéro pour les workers si vous en avez.

## Sauvegarde {#backup}

1. Obtenez le nom du service pour PostgreSQL. Le nom du service doit se terminer par `-postgres`. Dans cet exemple, le nom du service est `production-postgres`.

   ```shell
   $ kubectl get svc --namespace "$APP_NAMESPACE"
   NAME                     TYPE        CLUSTER-IP    EXTERNAL-IP   PORT(S)    AGE
   production-auto-deploy   ClusterIP   10.30.13.90   <none>        5000/TCP   7d14h
   production-postgres      ClusterIP   10.30.4.57    <none>        5432/TCP   7d14h
   ```

1. Obtenez le nom du pod pour PostgreSQL avec la commande suivante. Dans cet exemple, le nom du pod est `production-postgres-5db86568d7-qxlxv`.

   ```shell
   $ kubectl get pod --namespace "$APP_NAMESPACE" -l app=production-postgres
   NAME                                   READY   STATUS    RESTARTS   AGE
   production-postgres-5db86568d7-qxlxv   1/1     Running   0          7d14h
   ```

1. Connectez-vous au pod avec :

   ```shell
   kubectl exec -it production-postgres-5db86568d7-qxlxv --namespace "$APP_NAMESPACE" -- bash
   ```

1. Une fois connecté, créez un fichier dump avec la commande suivante.

   - `SERVICE_NAME` est le nom du service obtenu lors d'une étape précédente.
   - `USERNAME` est le nom d'utilisateur que vous avez configuré pour PostgreSQL. La valeur par défaut est `user`.
   - `DATABASE_NAME` est généralement le nom de l'environnement.
   - Lorsque le mot de passe de la base de données vous est demandé, la valeur par défaut est `testing-password`.

     ```shell
     ## Format is:
     # pg_dump -h SERVICE_NAME -U USERNAME DATABASE_NAME > /tmp/backup.sql

     pg_dump -h production-postgres -U user production > /tmp/backup.sql
     ```

1. Une fois le dump de sauvegarde terminé, quittez le processus exec Kubernetes avec <kbd>Control</kbd>-<kbd>D</kbd> ou `exit`.
1. Téléchargez le fichier dump avec la commande suivante :

   ```shell
   kubectl cp --namespace "$APP_NAMESPACE" production-postgres-5db86568d7-qxlxv:/tmp/backup.sql backup.sql
   ```

## Conserver les volumes persistants {#retain-persistent-volumes}

Par défaut, les [volumes persistants](https://kubernetes.io/docs/concepts/storage/persistent-volumes/) utilisés pour stocker les données sous-jacentes de PostgreSQL sont marqués comme `Delete` lorsque les pods et les réclamations de pods qui utilisent le volume sont supprimés.

Ceci est important car, lorsque vous optez pour le nouveau PostgreSQL 8.2.1, l'ancien PostgreSQL 0.7.1 est supprimé, entraînant également la suppression des volumes persistants.

Vous pouvez vérifier cela en utilisant la commande suivante :

```shell
$ kubectl get pv
NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                                                     STORAGECLASS   REASON   AGE
pvc-0da80c08-5239-11ea-9c8d-42010a8e0096   8Gi        RWO            Delete           Bound    minimal-ruby-app-4349298-staging/staging-postgres         standard                7d22h
pvc-9085e3d3-5239-11ea-9c8d-42010a8e0096   8Gi        RWO            Delete           Bound    minimal-ruby-app-4349298-production/production-postgres   standard                7d22h
```

Pour conserver le volume persistant, même lorsque l'ancien PostgreSQL 0.7.1 est supprimé, changez la politique de rétention en `Retain`. Dans cet exemple, les noms des volumes persistants sont trouvés en examinant les noms des réclamations. Pour conserver les volumes pour les environnements de staging et de production de l'application `minimal-ruby-app-4349298`, les noms des volumes sont `pvc-0da80c08-5239-11ea-9c8d-42010a8e0096` et `pvc-9085e3d3-5239-11ea-9c8d-42010a8e0096` :

```shell
$ kubectl patch pv  pvc-0da80c08-5239-11ea-9c8d-42010a8e0096 -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'
persistentvolume/pvc-0da80c08-5239-11ea-9c8d-42010a8e0096 patched
$ kubectl patch pv  pvc-9085e3d3-5239-11ea-9c8d-42010a8e0096 -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'
persistentvolume/pvc-9085e3d3-5239-11ea-9c8d-42010a8e0096 patched
$ kubectl get pv
NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                                                     STORAGECLASS   REASON   AGE
pvc-0da80c08-5239-11ea-9c8d-42010a8e0096   8Gi        RWO            Retain           Bound    minimal-ruby-app-4349298-staging/staging-postgres         standard                7d22h
pvc-9085e3d3-5239-11ea-9c8d-42010a8e0096   8Gi        RWO            Retain           Bound    minimal-ruby-app-4349298-production/production-postgres   standard                7d22h
```

## Installer le nouveau PostgreSQL {#install-new-postgresql}

> [!warning]
> L'utilisation de la version plus récente de PostgreSQL supprime l'ancien PostgreSQL 0.7.1. Pour éviter que les données sous-jacentes ne soient supprimées, vous pouvez choisir de conserver le [volume persistant](#retain-persistent-volumes).

Vous pouvez également modifier les étapes ci-dessous pour [limiter la portée](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable) des variables `AUTO_DEVOPS_POSTGRES_CHANNEL`, `AUTO_DEVOPS_POSTGRES_DELETE_V1` et `POSTGRES_VERSION` à des environnements spécifiques, par exemple `staging`.

1. Attribuez la valeur `2` à `AUTO_DEVOPS_POSTGRES_CHANNEL`. Cela permet d'utiliser le nouveau PostgreSQL basé sur la version 8.2.1, et supprime l'ancien PostgreSQL basé sur la version 0.7.1.
1. Définissez `AUTO_DEVOPS_POSTGRES_DELETE_V1` sur une valeur non vide. Ce drapeau est une protection pour éviter la suppression accidentelle de bases de données.
   <!-- DO NOT REPLACE when upgrading GitLab's supported version. This is NOT related to GitLab's PostgreSQL version support, but the one deployed by Auto DevOps. -->
1. Si vous avez défini `POSTGRES_VERSION`, assurez-vous qu'il est défini sur `9.6.16` ou une version ultérieure. Il s'agit de la version minimale de PostgreSQL prise en charge par Auto DevOps. Consultez également la liste des [tags disponibles](https://hub.docker.com/r/bitnami/postgresql/tags).
1. Attribuez la valeur `0` à `PRODUCTION_REPLICAS`. Pour les autres environnements, utilisez `REPLICAS` avec une [portée d'environnement](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable).
1. Si vous avez défini les variables `DB_INITIALIZE` ou `DB_MIGRATE`, supprimez-les ou renommez-les temporairement en `XDB_INITIALIZE` ou `XDB_MIGRATE` pour les désactiver efficacement.
1. Exécutez un nouveau pipeline CI pour la branche. Dans ce cas, exécutez un nouveau pipeline CI pour `main`.
1. Une fois le pipeline réussi, votre application est mise à niveau avec le nouveau PostgreSQL installé. Il n'existe aucun réplica à ce moment, de sorte qu'aucun trafic n'est traité pour votre application (pour empêcher l'entrée de nouvelles données).

## Restauration {#restore}

1. Obtenez le nom du pod pour le nouveau PostgreSQL ; dans cet exemple, le nom du pod est `production-postgresql-0` :

   ```shell
   $ kubectl get pod --namespace "$APP_NAMESPACE" -l app=postgresql
   NAME                      READY   STATUS    RESTARTS   AGE
   production-postgresql-0   1/1     Running   0          19m
   ````

1. Copiez le fichier dump des étapes de sauvegarde vers le pod :

   ```shell
   kubectl cp --namespace "$APP_NAMESPACE" backup.sql production-postgresql-0:/tmp/backup.sql
   ```

1. Connectez-vous au pod :

   ```shell
   kubectl exec -it production-postgresql-0 --namespace "$APP_NAMESPACE" -- bash
   ```

1. Une fois connecté au pod, exécutez la commande suivante pour restaurer la base de données.

   - Lorsque le mot de passe de la base de données vous est demandé, la valeur par défaut est `testing-password`.
   - `USERNAME` est le nom d'utilisateur que vous avez configuré pour PostgreSQL. La valeur par défaut est `user`.
   - `DATABASE_NAME` est généralement le nom de l'environnement.

   ```shell
   ## Format is:
   # psql -U USERNAME -d DATABASE_NAME < /tmp/backup.sql

   psql -U user -d production < /tmp/backup.sql
   ```

1. Vous pouvez maintenant vérifier que vos données ont été restaurées correctement une fois la restauration terminée. Vous pouvez effectuer des vérifications ponctuelles de vos données en utilisant `psql`.

## Rétablir votre application {#reinstate-your-application}

Une fois que vous êtes satisfait de la restauration de la base de données, exécutez les étapes suivantes pour rétablir votre application :

1. Restaurez les variables `DB_INITIALIZE` et `DB_MIGRATE`, si elles ont été précédemment supprimées ou désactivées.
1. Restaurez la variable `PRODUCTION_REPLICAS` ou `REPLICAS` à sa valeur d'origine.
1. Exécutez un nouveau pipeline CI pour la branche. Dans ce cas, exécutez un nouveau pipeline CI pour `main`. Une fois le pipeline réussi, votre application devrait traiter le trafic comme auparavant.
