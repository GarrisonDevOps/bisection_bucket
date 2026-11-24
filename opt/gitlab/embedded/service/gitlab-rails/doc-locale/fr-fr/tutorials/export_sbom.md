---
stage: Application Security Testing
group: Composition Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Apprenez à générer et à exporter une nomenclature logicielle (SBOM) au format CycloneDX pour les dépendances de votre projet, et à l'enregistrer en tant qu'artefact CI/CD."
title: 'Tutoriel : exporter la liste des dépendances au format SBOM'
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

La sortie de l'analyse des dépendances peut être exportée au format CycloneDX JSON.

Ce tutoriel vous montre comment générer un SBOM CycloneDX JSON pour un pipeline, puis le téléverser en tant qu'artefact de job CI.

## Avant de commencer {#before-you-begin}

Configurez l'analyse des dépendances. Pour des instructions détaillées, suivez [le tutoriel sur l'analyse des dépendances](dependency_scanning.md).

## Créer des fichiers de configuration {#create-configuration-files}

1. Créez un jeton d'accès privé avec la portée `api` et le rôle `Developer`.
1. Ajoutez la valeur du jeton en tant que variable CI/CD nommée `PRIVATE_TOKEN`.
1. Créez un [snippet](../api/snippets.md) avec le code suivant.

   Nom de fichier : `export.sh`

   ```shell
   #! /bin/sh

   function create_export {
     curl --silent \
     --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
     -X 'POST' --data "export_type=sbom" \
     "https://gitlab.com/api/v4/pipelines/$CI_PIPELINE_ID/dependency_list_exports" \
     | jq '.id'
   }

   function check_status {
     curl --silent \
       --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
       --write-out "%{http_code}" --output /dev/null \
       https://gitlab.com/api/v4/dependency_list_exports/$1
   }

   function download {
     curl --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
       --output "gl-sbom-merged-$CI_PIPELINE_ID.cdx.json" \
       "https://gitlab.com/api/v4/dependency_list_exports/$1/download"
   }

   function export_sbom {
     local ID=$(create_export)

     for run in $(seq 0 3); do
       local STATUS=$(check_status $ID)
       # Status is 200 when JSON is generated.
       # Status is 202 when generate JSON job is running.
       if [ $STATUS -eq "200" ]; then
         download $ID

         exit 0
       elif [ $STATUS -ne "202" ]; then
         exit 1
       fi

       echo "Waiting for JSON to be generated"
       sleep 5
     done

     exit 1
   }

   export_sbom
   ```

   Ce script `export.sh` fonctionne selon les étapes suivantes :

   1. Créer une exportation SBOM CycloneDX pour le pipeline actuel.
   1. Vérifier le statut de cette exportation et s'arrêter lorsqu'elle est prête.
   1. Télécharger le fichier SBOM CycloneDX.

1. Mettez à jour `.gitlab-ci.yml` avec le code suivant.

   ```yaml
   export-merged-sbom:
     image: alpine
     before_script:
       - apk add --update jq curl
     stage: .post
     script:
       - |
         curl --header "Authorization: Bearer $PRIVATE_TOKEN" --output export.sh --url "https://gitlab.com/api/v4/snippets/<SNIPPET_ID>/raw"
       - /bin/sh export.sh
     artifacts:
       paths:
         - "gl-sbom-merged-*.cdx.json"

   ```

1. Accédez à **Version** > **Pipelines** et confirmez que le dernier pipeline s'est terminé avec succès.

Dans les artefacts de job, le fichier `gl-sbom-merged-<pipeline_id>.cdx.json` doit être présent.
