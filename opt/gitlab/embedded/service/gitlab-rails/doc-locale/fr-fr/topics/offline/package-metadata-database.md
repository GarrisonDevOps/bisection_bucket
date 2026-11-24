---
stage: Application Security Testing
group: Composition Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Téléchargez la base de données de métadonnées de paquets et copiez-la sur une instance GitLab Self-Managed hors ligne.
title: Base de données de métadonnées de paquets pour les instances hors ligne
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

L'activation de la [base de données de métadonnées de paquets](../../user/application_security/detect/package-metadata-database.md) est requise pour activer [l'analyse continue des vulnérabilités](../../user/application_security/continuous_vulnerability_scanning/_index.md) et [l'analyse des licences des fichiers CycloneDX](../../user/compliance/license_scanning_of_cyclonedx_files/_index.md). Ce processus nécessite l'utilisation des données de licences et/ou des données de conseil dans ce qui est collectivement appelé la base de données de métadonnées de paquets, sous [licence EE](https://storage.googleapis.com/prod-export-license-bucket-1a6c642fc4de57d4/LICENSE). Notez ce qui suit concernant l'utilisation de la base de données de métadonnées de paquets :

- Nous pouvons modifier ou interrompre tout ou partie de la base de données de métadonnées de paquets, à tout moment et sans préavis, à notre seule discrétion.
- La base de données de métadonnées de paquets peut contenir des liens vers des sites web ou des ressources tiers. Nous fournissons ces liens uniquement pour des raisons pratiques et ne sommes pas responsables des données, contenus, produits ou services tiers provenant de ces sites web ou ressources, ni des liens affichés sur ces sites.
- La base de données de métadonnées de paquets est en partie fondée sur des informations mises à disposition par des tiers, et GitLab n'est pas responsable de l'exactitude ou de l'exhaustivité du contenu mis à disposition.

La base de données de métadonnées de paquets est composée de quatre jeux de données : les licences, les avis de sécurité, les avis de logiciels malveillants et l'enrichissement CVE. Les métadonnées de paquets sont publiées en deux versions de format, v2 et v3, et chaque jeu de données utilise l'une d'elles. Les deux versions de format contiennent des données différentes et sont téléchargées de différentes manières ; chacune dispose donc de sa propre procédure ci-dessous. Pour connaître la version de format utilisée par chaque jeu de données et chaque version de GitLab, consultez [la base de données de métadonnées de paquets](../../user/application_security/detect/package-metadata-database.md).

Les données v2 sont stockées dans les buckets publics Google Cloud Provider (GCP) suivants, qui sont maintenus et détenus par GitLab :

- License Scanning : `prod-export-license-bucket-1a6c642fc4de57d4`
- Analyse des dépendances : `prod-export-advisory-bucket-1a6c642fc4de57d4`
- Enrichissement CVE : `prod-export-cve-enrichment-bucket-1a6c642fc4de57d4`

Les données v3 ne disposent pas de bucket public. Elles sont distribuées par un service GitLab authentifié, et leur téléchargement nécessite donc une clé de licence. Consultez [Télécharger les données v3 de la base de données de métadonnées de paquets](#download-v3-package-metadata-database-data).

L'enrichissement CVE inclut le [score EPSS et le statut KEV](../../user/application_security/vulnerabilities/risk_assessment_data.md) affichés sur une vulnérabilité. Une instance qui synchronise uniquement les buckets de licences et d'avis de sécurité dispose des données d'analyse des dépendances et des données de licences, mais pas des données d'évaluation des risques.

> [!note]
> Pour chaque jeu de données, GitLab lit le répertoire sous `vendor/package_metadata` chaque fois qu'il existe, en priorité par rapport au téléchargement des données elles-mêmes. Un répertoire présent l'emporte toujours, et il n'y a pas de basculement vers la synchronisation en ligne. Un répertoire contenant des données obsolètes renvoie donc des données obsolètes, sans signaler d'erreur. Les [avis de logiciels malveillants](#confirm-gitlab-detects-the-offline-directory) suivent la même règle.

## Avant le premier chargement {#before-the-first-load}

Décidez des types de registres de paquets à synchroniser avant de télécharger quoi que ce soit. Seuls les types activés dans les [paramètres d'administration](../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync) sont importés. Si vous téléchargez un type que vous avez désactivé, cela coûte du temps et de l'espace disque, et rien n'atteint la base de données.

Un limiteur dans le job de synchronisation définit le taux d'importation, et non les ressources de l'instance ; une instance plus grande n'importe donc pas plus rapidement. Chaque exécution s'arrête également après une durée fixe et reprend depuis son point de contrôle lors de la prochaine exécution. Un premier chargement avec tous les types de registres activés prend beaucoup de temps. Pour le raccourcir, réduisez le nombre de types activés.

## Télécharger les métadonnées de paquets v2 avec gsutil {#download-v2-package-metadata-with-gsutil}

Cette section décrit comment télécharger les données v2.

1. Installez l'outil [`gsutil`](https://docs.cloud.google.com/storage/docs/gsutil_install).
1. Trouvez la racine du répertoire GitLab Rails.

   ```shell
   export GITLAB_RAILS_ROOT_DIR="$(gitlab-rails runner 'puts Rails.root.to_s')"
   echo $GITLAB_RAILS_ROOT_DIR
   ```

1. Définissez le type de données que vous souhaitez synchroniser.

   ```shell
   # For License Scanning
   export PKG_METADATA_BUCKET=prod-export-license-bucket-1a6c642fc4de57d4
   export DATA_DIR="licenses"

   # For dependency scanning
   export PKG_METADATA_BUCKET=prod-export-advisory-bucket-1a6c642fc4de57d4
   export DATA_DIR="advisories"

   # For CVE enrichment
   export PKG_METADATA_BUCKET=prod-export-cve-enrichment-bucket-1a6c642fc4de57d4
   export DATA_DIR="cve_enrichment"
   ```

1. Téléchargez les exports de métadonnées de paquets.

   ```shell
   # To download the package metadata exports, an outbound connection to Google Cloud Storage bucket must be allowed.
   mkdir -p "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/$DATA_DIR"
   gsutil -m rsync -r -d gs://$PKG_METADATA_BUCKET "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/$DATA_DIR"

   # Alternatively, if the GitLab instance is not allowed to connect to the Google Cloud Storage bucket, the package metadata
   # exports can be downloaded using a machine with the allowed access, and then copied to the root of the GitLab Rails directory.
   rsync rsync://example_username@gitlab.example.com/package_metadata/$DATA_DIR "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/$DATA_DIR"
   ```

1. Pour l'enrichissement CVE dans GitLab 19.4 et versions antérieures, déplacez les fichiers téléchargés d'un niveau de répertoire vers le haut. Dans GitLab 19.5 et versions ultérieures, ignorez cette étape. Pour plus d'informations, consultez la [merge request 253401](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253401).

   Les buckets de licences et d'avis de sécurité contiennent un répertoire par registre de paquets sous `v2/`, et GitLab lit une copie de ces répertoires tels quels. L'enrichissement CVE ne dispose pas de registre de paquets, et son bucket contient à la place un seul répertoire `cve_enrichment` à cette position. Dans GitLab 19.4 et versions antérieures, GitLab lit l'enrichissement CVE uniquement depuis `cve_enrichment/v2/<sequence>/<chunk>.ndjson`, à cette profondeur exacte. Une copie telle quelle laisse les fichiers à un niveau de répertoire trop profond. GitLab n'importe alors rien et ne consigne rien.

   ```shell
   cd "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment/v2"
   cp -a cve_enrichment/. . && rm -r cve_enrichment
   ```

   Répétez cette étape après chaque téléchargement de l'export d'enrichissement CVE. `cp -a` fusionne les nouveaux fichiers dans les répertoires de séquences qui existent déjà, là où `mv` s'arrêterait.

## Télécharger les métadonnées de paquets v2 à l'aide de l'API REST Google Cloud Storage {#download-v2-package-metadata-using-the-google-cloud-storage-rest-api}

Cette section décrit une autre manière de télécharger les métadonnées de paquets v2.

Les exports de métadonnées de paquets peuvent également être téléchargés à l'aide de l'API Google Cloud Storage. Le contenu est disponible à l'adresse <https://storage.googleapis.com/storage/v1/b/prod-export-license-bucket-1a6c642fc4de57d4/o> et <https://storage.googleapis.com/storage/v1/b/prod-export-advisory-bucket-1a6c642fc4de57d4/o>. Voici un exemple de la façon dont ce téléchargement peut être effectué à l'aide de [cURL](https://curl.se/) et de [jq](https://stedolan.github.io/jq/).

```shell
#!/bin/bash

set -euo pipefail

DATA_TYPE=$1

GITLAB_RAILS_ROOT_DIR="$(gitlab-rails runner 'puts Rails.root.to_s')"

if [ "$DATA_TYPE" == "license" ]; then
  PKG_METADATA_DIR="$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses"
elif [ "$DATA_TYPE" == "advisory" ]; then
  PKG_METADATA_DIR="$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/advisories"
else
  echo "Usage: import_script.sh [license|advisory]"
  exit 1
fi

PKG_METADATA_BUCKET="prod-export-$DATA_TYPE-bucket-1a6c642fc4de57d4"
PKG_METADATA_DOWNLOADS_OUTPUT_FILE="/tmp/package_metadata_${DATA_TYPE}_object_links.tsv"

# Download the contents of the bucket
# The script downloads all the objects and creates files with a maximum 1000 objects per file in JSON format.

MAX_RESULTS=1000
TEMP_FILE="out.json"

curl --silent --show-error --request GET "https://storage.googleapis.com/storage/v1/b/$PKG_METADATA_BUCKET/o?maxResults=$MAX_RESULTS" >"$TEMP_FILE"
NEXT_PAGE_TOKEN="$(jq -r '.nextPageToken' $TEMP_FILE)"
jq -r '.items[] | [.name, .mediaLink] | @tsv' "$TEMP_FILE" >"$PKG_METADATA_DOWNLOADS_OUTPUT_FILE"

while [ "$NEXT_PAGE_TOKEN" != "null" ]; do
  curl --silent --show-error --request GET "https://storage.googleapis.com/storage/v1/b/$PKG_METADATA_BUCKET/o?maxResults=$MAX_RESULTS&pageToken=$NEXT_PAGE_TOKEN" >"$TEMP_FILE"
  NEXT_PAGE_TOKEN="$(jq -r '.nextPageToken' $TEMP_FILE)"
  jq -r '.items[] | [.name, .mediaLink] | @tsv' "$TEMP_FILE" >>"$PKG_METADATA_DOWNLOADS_OUTPUT_FILE"
  #use for API rate-limiting
  sleep 1
done

trap 'rm -f "$TEMP_FILE"' EXIT

echo "Fetched $DATA_TYPE export manifest"

# Parse the links and names for the bucket objects and output them into a tsv file

echo -e "Saving package metadata exports to $PKG_METADATA_DIR\n"

# Track how many objects will be downloaded
INDEX=1
TOTAL_OBJECT_COUNT="$(wc -l "$PKG_METADATA_DOWNLOADS_OUTPUT_FILE" | awk '{print $1}')"

# Download the objects
while IFS= read -r line; do
  FILE="$(echo -n "$line" | awk '{print $1}')"
  URL="$(echo -n "$line" | awk '{print $2}')"
  OUTPUT_PATH="$PKG_METADATA_DIR/$FILE"

  echo "Downloading $FILE"

  if [ ! -f "$OUTPUT_PATH" ]; then
    curl --progress-bar --create-dirs --output "$OUTPUT_PATH" --request "GET" "$URL"
  else
    echo "Existing file found"
  fi

  echo -e "$INDEX of $TOTAL_OBJECT_COUNT objects downloaded\n"

  INDEX=$((INDEX + 1))
done <"$PKG_METADATA_DOWNLOADS_OUTPUT_FILE"

echo "All objects saved to $PKG_METADATA_DIR"
```

## Télécharger les métadonnées de paquets v2 selon un calendrier {#download-v2-package-metadata-on-a-schedule}

Votre instance GitLab est synchronisée [régulièrement](https://gitlab.com/gitlab-org/gitlab/-/blob/63a187d47f6da353ba4514650bbbbeb99c356325/config/initializers/1_settings.rb#L840-842) avec le contenu du répertoire `package_metadata`. Pour mettre à jour automatiquement votre copie locale avec les modifications en amont, un job cron peut être ajouté pour télécharger périodiquement de nouveaux exports. Par exemple, les crontabs suivants peuvent être ajoutés pour configurer un job cron qui s'exécute toutes les 30 minutes.

Les jobs de licences et d'avis de sécurité transmettent `-y "^v3\/"` pour exclure le dossier `v3/`, afin de ne refléter que la version de format v2.

Pour l'analyse des licences v2 (GitLab 19.3 et versions antérieures) :

```plaintext
*/30 * * * * gsutil -m rsync -r -d -y "^v3\/" gs://prod-export-license-bucket-1a6c642fc4de57d4 $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses
```

Pour l'analyse des dépendances v2 :

```plaintext
*/30 * * * * gsutil -m rsync -r -d -y "^v3\/" gs://prod-export-advisory-bucket-1a6c642fc4de57d4 $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/advisories
```

Pour l'enrichissement CVE dans GitLab 19.4 et versions antérieures, omettez `-d` et enchaînez l'étape de déplacement de la procédure de téléchargement :

```plaintext
*/30 * * * * gsutil -m rsync -r gs://prod-export-cve-enrichment-bucket-1a6c642fc4de57d4 $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment && cd $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment/v2 && cp -a cve_enrichment/. . && rm -r cve_enrichment
```

Après l'étape de déplacement, la disposition locale ne correspond plus au bucket, et `-d` supprimerait les fichiers déplacés. Le déplacement supprime également le répertoire contre lequel `gsutil rsync` effectue ses comparaisons, de sorte que chaque exécution re-télécharge l'intégralité de l'export, que `-d` soit présent ou non.

Dans GitLab 19.5 et versions ultérieures, effectuez le téléchargement sans l'étape de déplacement. Si vous effectuez une mise à niveau depuis une version antérieure, remplacez votre ligne d'enrichissement CVE existante par la suivante :

```plaintext
*/30 * * * * gsutil -m rsync -r -d gs://prod-export-cve-enrichment-bucket-1a6c642fc4de57d4 $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment
```

> [!warning]
> L'indicateur `-d` dans les exemples de licences et d'avis de sécurité, ainsi que dans l'exemple d'enrichissement CVE dans GitLab 19.5 et versions ultérieures, supprime les fichiers locaux qui ne sont plus dans le bucket, ce qui peut annuler une importation en cours. GitLab enregistre le dernier fichier importé pour chaque type de données et registre de paquets, et reprend depuis le fichier suivant. Si un élagage supprime le répertoire de séquences vers lequel pointe cet enregistrement, GitLab ne peut pas trouver l'enregistrement. Il importe alors à nouveau l'intégralité du type de données depuis le début. Avant d'élaguer, vérifiez que la séquence enregistrée pour chaque type de données est toujours sur le disque. Pour lire les séquences enregistrées, consultez [Vérifier les données](#verify-data). Sur un répertoire lu par plusieurs instances, n'élaguez qu'en deçà de la séquence la plus ancienne enregistrée par l'une d'entre elles.
>
> Ce comportement s'applique aux exports de licences, d'avis de sécurité et d'enrichissement CVE, que GitLab importe un fichier à la fois. La [procédure concernant les avis de logiciels malveillants](#download-gitlab-v3-malware-advisories) est différente. Elle remplace un instantané complet à chaque exécution, et `rsync --delete` est requis.

## Télécharger les données v3 de la base de données de métadonnées de paquets {#download-v3-package-metadata-database-data}

{{< details >}}

- Édition : GitLab Ultimate

{{< /details >}}

Les licences v3 et les avis de logiciels malveillants ne se trouvent pas dans un bucket public. Ils proviennent d'un service GitLab authentifié, le service de distribution de la base de données de métadonnées de paquets (PDS), et une instance hors ligne ne peut donc pas les télécharger directement. Exécutez plutôt le script suivant sur une machine disposant d'un accès à Internet, puis copiez les données sur l'instance hors ligne. Le script fonctionne pour les deux jeux de données. Passez le nom du jeu de données comme premier argument.

Pour chaque registre de paquets, le script télécharge les deltas publiés depuis l'instantané déjà sur le disque, ou un nouvel instantané lorsqu'il n'y en a pas et lorsqu'un registre est trop en retard pour que les deltas soient l'option la moins coûteuse. Il écrit le point de contrôle de chaque registre en dernier, après le téléchargement de toutes les archives de ce registre, de sorte qu'un téléchargement partiel n'est jamais confondu avec un téléchargement complet. Il échange votre clé de licence contre un jeton valide trois jours. La machine disposant d'un accès à Internet a besoin d'une copie de votre fichier de licence, mais n'a pas besoin d'accéder à l'instance hors ligne.

Prérequis :

- Disposer d'un accès administrateur.
- Une licence hors ligne. Un fichier de licence hérité ne fonctionne pas : la demande de jeton échoue avec `Invalid cloud license` et le script s'arrête. Le tableau de bord de la zone **Admin** affiche votre type de licence sous **Aperçu des licences**.
- Sur la machine disposant d'un accès à Internet, cURL, jq 1.6 ou version ultérieure, et un accès sortant vers `customers.gitlab.com`, `pmdb-dist-svc.runway.gitlab.net` et `storage.googleapis.com`. Le service de distribution est sur le domaine `gitlab.net`, donc une liste d'autorisation limitée à `gitlab.com` ne peut pas l'atteindre.
- Sur l'instance hors ligne, rsync.

Pour obtenir une licence hors ligne, vous devez recevoir une [exemption d'opt-out de la licence cloud](https://about.gitlab.com/pricing/licensing-faq/cloud-licensing/#offline-cloud-licensing), ce qui nécessite une approbation. Pour plus de détails, contactez votre représentant commercial GitLab. Si vous disposez déjà d'une licence hors ligne, vous pouvez télécharger à nouveau le fichier depuis le [portail clients](https://customers.gitlab.com).

Le script a besoin de la clé de licence, qui est le long bloc de texte contenu dans le fichier de licence. Pour l'écrire dans un fichier, exécutez la commande suivante sur l'instance hors ligne :

```shell
sudo gitlab-rails runner 'puts License.current.data' > Gitlab.gitlab-license
```

Un code d'activation n'est pas une clé de licence. Un code d'activation est une courte chaîne de caractères, et la demande de jeton le rejette.

Ces étapes s'appliquent aux installations de paquets Linux. Dans les installations Kubernetes, les données doivent se trouver sur un volume lu par les pods Sidekiq. Consultez [Instances installées avec le chart Helm](#instances-installed-with-the-helm-chart).

> [!warning]
> Dans les installations Docker, le répertoire Rails ne se trouve pas sur un volume monté. Montez `vendor/package_metadata` en bind mount avant de copier les données, sinon elles seront perdues lors de la mise à niveau du conteneur.

Enregistrez le script suivant sous `download_pmdb_data.sh` et rendez-le exécutable avec `chmod +x download_pmdb_data.sh`.

```shell
#!/bin/bash

set -euo pipefail

CDOT_URL="${CDOT_URL:-https://customers.gitlab.com}"
PDS_URL="${PDS_URL:-https://pmdb-dist-svc.runway.gitlab.net}"

# A registry far enough behind is cheaper to replace with a fresh snapshot than
# to catch up one delta at a time. Set to 0 to never download a delta.
MAX_DELTAS="${MAX_DELTAS:-100}"

if [ $# -lt 5 ]; then
  echo "Usage: download_pmdb_data.sh <license_file> <gitlab_version> <dataset> <output_dir> <registry>"
  echo "dataset is licenses or malware_advisories."
  echo "Pass the package registries to download separated by space, or 'all' for every supported registry."
  exit 1
fi

LICENSE_FILE=$1
GITLAB_VERSION=$2
DATASET=$3
OUTPUT_DIR=$4
shift 4
REQUESTED_REGISTRIES="$*"

# The two datasets differ only in their distribution service path and the name
# used in the closing message. Everything after this point is common to both.
case "$DATASET" in
licenses)
  DATASET_PATH="licenses"
  DATASET_LABEL="License data"
  ;;
malware_advisories)
  DATASET_PATH="malware/advisories"
  DATASET_LABEL="Advisories"
  ;;
*)
  echo "dataset must be licenses or malware_advisories"
  exit 1
  ;;
esac

if [ -z "$OUTPUT_DIR" ]; then
  echo "output_dir must not be empty"
  exit 1
fi

if [ ! -r "$LICENSE_FILE" ]; then
  echo "Cannot read $LICENSE_FILE"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Serialize runs against this output directory. Two concurrent runs would race
# on the same dataset directory: one can write checkpoint.json while the other
# has deleted and re-created the directory, leaving a partial shard set that
# GitLab imports as a complete snapshot. mkdir either creates the directory or
# fails, in one step, so it needs nothing beyond the shell.
LOCK_DIR="$OUTPUT_DIR/.download.lock"

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "Another download is already running for $OUTPUT_DIR"
  echo "If no other run is active, remove $LOCK_DIR and try again."
  exit 1
fi

REQUEST_FILE="$(mktemp)"
RESPONSE_FILE="$(mktemp)"
SNAPSHOT_FILE="$(mktemp)"
SHARDS_FILE="$(mktemp)"
DELTAS_FILE="$(mktemp)"
HEADER_FILE="$(mktemp)"
trap 'rm -f "$REQUEST_FILE" "$RESPONSE_FILE" "$SNAPSHOT_FILE" "$SHARDS_FILE" "$DELTAS_FILE" "$HEADER_FILE"; rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT
chmod 600 "$HEADER_FILE"

# Exchange the license key for a Cloud Connector token.
GRAPHQL_QUERY='query($licenseKey: String!, $gitlabVersion: String!) {
  cloudConnectorAccess(licenseKey: $licenseKey, gitlabVersion: $gitlabVersion) {
    serviceToken { token }
  }
}'

jq --null-input --arg query "$GRAPHQL_QUERY" --rawfile licenseKey "$LICENSE_FILE" \
  --arg gitlabVersion "$GITLAB_VERSION" \
  '{query: $query, variables: {licenseKey: $licenseKey, gitlabVersion: $gitlabVersion}}' >"$REQUEST_FILE"

HTTP_STATUS="$(curl --silent --show-error --request POST "$CDOT_URL/graphql" \
  --header 'Content-Type: application/json' --data @"$REQUEST_FILE" \
  --output "$RESPONSE_FILE" --write-out '%{http_code}')"

if [ "$HTTP_STATUS" != "200" ]; then
  echo "Token request to $CDOT_URL failed with HTTP $HTTP_STATUS"
  head -c 500 "$RESPONSE_FILE"
  exit 1
fi

TOKEN="$(jq --raw-output '.data.cloudConnectorAccess.serviceToken.token // empty' "$RESPONSE_FILE")"

if [ -z "$TOKEN" ]; then
  echo "$CDOT_URL refused to issue a token for $LICENSE_FILE"
  echo "It must hold the license key, the output of: gitlab-rails runner 'puts License.current.data'"
  echo "An activation code is not a license key, and a legacy license is not accepted."
  echo "The customer portal reported:"
  jq --raw-output '.errors[]?.message // "no reason given"' "$RESPONSE_FILE"
  exit 1
fi

# The distribution service requires X-Gitlab-Instance-Id to equal the token's
# subject claim and X-Gitlab-Realm to equal its realm claim. Both are in the
# payload, which is the second dot-separated segment of the token.
CLAIMS="$(printf '%s' "$TOKEN" |
  jq --raw-input 'split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson')"

INSTANCE_ID="$(jq --raw-output '.sub // empty' <<<"$CLAIMS")"
REALM="$(jq --raw-output '.gitlab_realm // empty' <<<"$CLAIMS")"

if [ -z "$INSTANCE_ID" ] || [ -z "$REALM" ]; then
  echo "The token is missing its subject or realm claim"
  exit 1
fi

# Pass the headers through a file so the token never appears in a process
# list. It is readable there by any local user for the download's duration.
{
  printf 'header = "Authorization: Bearer %s"\n' "$TOKEN"
  printf 'header = "X-Gitlab-Instance-Id: %s"\n' "$INSTANCE_ID"
  printf 'header = "X-Gitlab-Realm: %s"\n' "$REALM"
} >"$HEADER_FILE"

# Writes the response body to $2 and returns the HTTP status.
pds_request() {
  curl --silent --show-error --config "$HEADER_FILE" \
    --output "$2" --write-out '%{http_code}' "$1"
}

HTTP_STATUS="$(pds_request "$PDS_URL/v1/$DATASET_PATH/supported" "$RESPONSE_FILE")"

if [ "$HTTP_STATUS" != "200" ]; then
  echo "Request for the supported package registries failed with HTTP $HTTP_STATUS"
  head -c 500 "$RESPONSE_FILE"
  exit 1
fi

SUPPORTED="$(jq --raw-output '.registries[]' "$RESPONSE_FILE")"
SKIPPED=""

if [ -z "$SUPPORTED" ]; then
  echo "No package registries are available"
  exit 1
fi

echo "Available package registries: $(echo "$SUPPORTED" | tr '\n' ' ')"

# Disable filename expansion so a registry name is never treated as a glob.
set -f

if [ "$REQUESTED_REGISTRIES" = "all" ]; then
  REGISTRIES="$SUPPORTED"
else
  REGISTRIES="$REQUESTED_REGISTRIES"

  for REGISTRY in $REGISTRIES; do
    if ! grep --quiet --fixed-strings --line-regexp "$REGISTRY" <<<"$SUPPORTED"; then
      echo "$REGISTRY is not a supported package registry"
      exit 1
    fi
  done
fi

# Downloads the current snapshot into a registry's full_dataset directory, and
# removes any delta archives beside it: a snapshot supersedes every delta older
# than itself, and GitLab reads whatever is newer than its own checkpoint, so
# leaving them would re-apply changes the snapshot already contains.
download_snapshot() {
  REGISTRY=$1
  UNTIL=$2
  DATASET_DIR="$OUTPUT_DIR/v3/$REGISTRY/full_dataset"

  # Remove any previous snapshot. GitLab reads every archive in this directory,
  # so archives left over from an earlier snapshot would be imported alongside
  # the new ones, restoring data that changed since.
  rm -rf "$DATASET_DIR" "$OUTPUT_DIR/v3/$REGISTRY/deltas"
  mkdir -p "$DATASET_DIR"

  # Read the shards from the saved /all body. The delta loop reuses
  # $RESPONSE_FILE, so by the time a fallback lands here it no longer holds it.
  jq --raw-output '.shards[] | [.shard, (.signed_url // .url)] | @tsv' "$SNAPSHOT_FILE" >"$SHARDS_FILE"
  SHARD_COUNT="$(wc -l <"$SHARDS_FILE" | tr -d ' ')"

  while IFS=$'\t' read -r SHARD URL; do
    echo "Downloading $REGISTRY snapshot archive $SHARD"
    curl --fail --silent --show-error --location --output "$DATASET_DIR/$SHARD.tar.zst.part" "$URL"
    mv "$DATASET_DIR/$SHARD.tar.zst.part" "$DATASET_DIR/$SHARD.tar.zst"
  done <"$SHARDS_FILE"

  # Write the checkpoint last. GitLab ignores a directory that has no
  # checkpoint, so an interrupted download is never imported as a snapshot.
  jq --null-input --argjson until "$UNTIL" --argjson shards "$SHARD_COUNT" \
    '{until: $until, shards: $shards}' >"$DATASET_DIR/checkpoint.json"
}

for REGISTRY in $REGISTRIES; do
  HTTP_STATUS="$(pds_request "$PDS_URL/v1/$DATASET_PATH/all?purl_type=$REGISTRY" "$RESPONSE_FILE")"

  # A pending snapshot is the only skippable outcome. Every other 503 is
  # transient, and treating it as "no data" would delete a registry that the
  # instance already has.
  if [ "$HTTP_STATUS" = "503" ]; then
    # A 503 from in front of the service has no JSON body, so keep the reason
    # empty rather than letting jq abort the script.
    REASON="$(jq --raw-output '.reason // empty' "$RESPONSE_FILE" 2>/dev/null || true)"

    if [ "$REASON" = "snapshot_not_yet_published" ]; then
      echo "Skipping $REGISTRY, no snapshot is published yet"
      SKIPPED="$SKIPPED $REGISTRY"
      continue
    fi

    echo "Request for $REGISTRY failed with HTTP 503, try again later ($REASON)"
    exit 1
  fi

  if [ "$HTTP_STATUS" != "200" ]; then
    echo "Request for $REGISTRY failed with HTTP $HTTP_STATUS"
    head -c 500 "$RESPONSE_FILE"
    exit 1
  fi

  # Keep the /all body: the snapshot is the fallback for every branch below,
  # and the delta loop writes over $RESPONSE_FILE before one can be taken.
  cp "$RESPONSE_FILE" "$SNAPSHOT_FILE"

  UNTIL="$(jq --raw-output '.until // empty' "$SNAPSHOT_FILE")"

  if [ -z "$UNTIL" ]; then
    echo "The response for $REGISTRY has no snapshot timestamp"
    exit 1
  fi

  REGISTRY_DIR="$OUTPUT_DIR/v3/$REGISTRY"
  LOCAL_UNTIL="$(jq --raw-output '.until // empty' \
    "$REGISTRY_DIR/full_dataset/checkpoint.json" 2>/dev/null || true)"

  # Take the whole snapshot unless the output directory already holds one this
  # run can continue from. A delta cannot bootstrap a registry, and `since` has
  # to be a 10-digit unix-seconds value or the service answers 400, so a
  # checkpoint that is missing, unreadable or in another unit starts over.
  if ! [[ "$LOCAL_UNTIL" =~ ^[0-9]{10}$ ]]; then
    download_snapshot "$REGISTRY" "$UNTIL"
    continue
  fi

  # Resume from the newest archive on disk, snapshot or delta, which is where
  # GitLab's own checkpoint ends up once it has imported them. Asking from an
  # older timestamp would download deltas that are already here. Names that are
  # not a bare timestamp are ignored, matching what the connector reads.
  SINCE="$(find "$REGISTRY_DIR/deltas" -type f -name '*.tar.zst' 2>/dev/null |
    sed -e 's#.*/##' -e 's#\.tar\.zst$##' | grep -E '^[0-9]{10}$' |
    sort -n | tail -1 || true)"

  if [ -z "$SINCE" ] || [ "$LOCAL_UNTIL" -gt "$SINCE" ]; then
    SINCE="$LOCAL_UNTIL"
  fi

  # With deltas disabled, the published snapshot decides everything.
  if [ "$MAX_DELTAS" -le 0 ]; then
    if [ "$UNTIL" -gt "$LOCAL_UNTIL" ]; then
      echo "Replacing $REGISTRY, the published snapshot moved to $UNTIL"
      download_snapshot "$REGISTRY" "$UNTIL"
    else
      echo "Skipping $REGISTRY, snapshot $LOCAL_UNTIL is already downloaded"
    fi
    continue
  fi

  # Page forward. The service caps a response at 20 archives per registry and
  # sends the oldest of the backlog first, so re-asking from the newest archive
  # received walks the whole backlog without gaps.
  : >"$DELTAS_FILE"
  DELTA_TOTAL=0
  CAPPED=""

  while :; do
    HTTP_STATUS="$(pds_request "$PDS_URL/v1/$DATASET_PATH/delta?since=$REGISTRY:$SINCE" "$RESPONSE_FILE")"

    if [ "$HTTP_STATUS" != "200" ]; then
      echo "Delta request for $REGISTRY failed with HTTP $HTTP_STATUS"
      head -c 500 "$RESPONSE_FILE"
      exit 1
    fi

    # Registries are keyed by the identifier /supported gave us, and one that is
    # up to date comes back as an empty array rather than being left out.
    PAGE_COUNT="$(jq --arg r "$REGISTRY" '.purl_types[$r] // [] | length' "$RESPONSE_FILE")"

    if [ "$PAGE_COUNT" -eq 0 ]; then
      break
    fi

    jq --raw-output --arg r "$REGISTRY" \
      '.purl_types[$r] | sort_by(.delta | tonumber) | .[] | [.delta, (.signed_url // .url)] | @tsv' \
      "$RESPONSE_FILE" >>"$DELTAS_FILE"

    DELTA_TOTAL=$((DELTA_TOTAL + PAGE_COUNT))
    SINCE="$(cut -f1 "$DELTAS_FILE" | tail -1)"

    # Past the ceiling, one snapshot is fewer bytes than the rest of the backlog.
    if [ "$DELTA_TOTAL" -gt "$MAX_DELTAS" ]; then
      CAPPED=yes
      break
    fi
  done

  if [ -n "$CAPPED" ]; then
    echo "Replacing $REGISTRY, it is more than $MAX_DELTAS deltas behind"
    download_snapshot "$REGISTRY" "$UNTIL"
    continue
  fi

  if [ "$DELTA_TOTAL" -eq 0 ]; then
    echo "Skipping $REGISTRY, it is up to date at $SINCE"
    continue
  fi

  # Deltas sit beside the snapshot rather than replacing it: GitLab reads the
  # snapshot on a first sync and the deltas on every sync after it.
  mkdir -p "$REGISTRY_DIR/deltas"

  while IFS=$'\t' read -r DELTA URL; do
    echo "Downloading $REGISTRY delta $DELTA"
    curl --fail --silent --show-error --location \
      --output "$REGISTRY_DIR/deltas/$DELTA.tar.zst.part" "$URL"
    mv "$REGISTRY_DIR/deltas/$DELTA.tar.zst.part" "$REGISTRY_DIR/deltas/$DELTA.tar.zst"
  done <"$DELTAS_FILE"

  echo "Downloaded $DELTA_TOTAL delta(s) for $REGISTRY"
done

set +f

if [ -n "$SKIPPED" ]; then
  echo "Warning: no snapshot is published yet for:$SKIPPED"
  echo "The downloaded registries are complete and safe to copy. Run the script again later to pick up the rest."
fi

echo "$DATASET_LABEL saved to $OUTPUT_DIR"
```

Appelez le script comme suit :

```shell
./download_pmdb_data.sh <license_file> <gitlab_version> <dataset> <output_dir> <registry>
```

Le tableau suivant décrit ce que représente chaque indicateur du script :

| Argument         | Description |
|------------------|-------------|
| `license_file`   | Chemin vers un fichier contenant la clé de licence de l'instance, qui est le résultat de `sudo gitlab-rails runner 'puts License.current.data'`. Un code d'activation n'est pas une clé de licence. |
| `gitlab_version` | Version de l'instance GitLab qui importe les données, qui est le résultat de `sudo gitlab-rails runner 'puts Gitlab::VERSION'`. Par exemple, `19.4.0-ee`. |
| `dataset`        | `licenses` ou `malware_advisories`. |
| `output_dir`     | Répertoire dans lequel écrire. Créé s'il n'existe pas. Utilisez le même répertoire à chaque exécution, afin qu'un instantané inchangé soit ignoré. |
| `registry`   | Un ou plusieurs registres de paquets, par exemple `npm` ou `pypi`, ou `all` pour tous les registres pris en charge. Transmettez les registres dont les types sont activés dans les [paramètres d'administration](../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync). Les registres multiples doivent être séparés par un espace. Le script affiche la liste des registres pris en charge avant de télécharger quoi que ce soit. |

Le script crée un répertoire par registre de paquets, nommé d'après l'identifiant du registre plutôt que le type de paquet, par exemple :

```plaintext
licenses/
└── v3/
    └── npm/
        ├── full_dataset/
        │   ├── 00.tar.zst
        │   ├── 01.tar.zst
        │   ├── ...
        │   ├── 7f.tar.zst
        │   └── checkpoint.json
        └── deltas/
            ├── 1757520000.tar.zst
            └── 1757606400.tar.zst
```

Chaque archive d'instantané est nommée d'après son identifiant de fragment hexadécimal. Le nombre d'archives par registre est défini par le service, et une archive ne contenant aucune donnée est attendue. Chaque archive delta est nommée d'après l'horodatage Unix qui marque la fin de sa fenêtre. Pour ce que GitLab lit dans ces dossiers, consultez [la version de format des données de licences v3](#v3-license-data-format-version).

La première exécution pour un registre télécharge un instantané complet, et les exécutions ultérieures ne demandent que ce que le service a publié après la dernière archive déjà présente dans le répertoire de sortie.

> [!note]
> Réutilisez le même répertoire de sortie à chaque exécution, sinon le script n'a rien depuis lequel reprendre et télécharge à nouveau un instantané complet.

Le script remplace l'instantané et supprime le dossier `deltas/` adjacent lorsque le registre a plus de `MAX_DELTAS` archives de retard. Un instantané plus récent que les deltas adjacents est attendu, car le service le reconstruit selon son propre calendrier, et le script continue à lire les deltas plutôt que de télécharger à nouveau cet instantané. `MAX_DELTAS` est par défaut à 100, et le service sert au maximum 20 archives delta par requête. Définissez-le sur `0` pour ne jamais télécharger de delta, ce qui restaure le comportement antérieur consistant à remplacer l'instantané à chaque exécution.

Le script crée également un verrou sur le répertoire de sortie ; ainsi, si vous le relancez alors que le premier passage est encore en train d'écrire les données, le script se termine plutôt que de corrompre le répertoire. Lorsqu'il n'y a rien de plus récent que ce que le répertoire de sortie contient déjà, le script ignore ce registre et peut donc être exécuté en toute sécurité selon un calendrier.

Copiez chaque jeu de données à son emplacement en suivant les étapes de sa propre section : [données de licences](#download-v3-license-data) et [avis de logiciels malveillants](#download-gitlab-v3-malware-advisories).

## Télécharger les avis de logiciels malveillants GitLab v3 {#download-gitlab-v3-malware-advisories}

{{< details >}}

- Édition : GitLab Ultimate

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/epics/20876) dans GitLab 19.3 [avec les feature flags](../../administration/feature_flags/_index.md) `sync_malware_advisories` et `ingest_malware_advisories`. Activés par défaut.
- [Passage en disponibilité générale](https://gitlab.com/groups/gitlab-org/-/epics/20876) dans GitLab 19.5. Les feature flags `sync_malware_advisories` et `ingest_malware_advisories` ont été supprimés.

{{< /history >}}

> [!note]
> En plus de GitLab Ultimate, cette fonctionnalité est disponible pour les clients Premium disposant du module complémentaire de pare-feu des dépendances.

Les [avis GitLab sur les logiciels malveillants](../../user/application_security/gitlab_advisory_database/_index.md#gitlab-advisories-for-malware) couvrent les paquets malveillants connus trouvés dans les registres de paquets. Ils sont distribués par le service de distribution de la base de données de métadonnées de paquets ; vous les téléchargez donc sur une machine disposant d'un accès à Internet et vous les copiez sur l'instance hors ligne. Téléchargez-les avec le script partagé et ses prérequis, décrits dans [Télécharger les données v3 de la base de données de métadonnées de paquets](#download-v3-package-metadata-database-data) :

```shell
./download_pmdb_data.sh ./Gitlab.gitlab-license 19.3.0-ee malware_advisories ./malware_advisories npm pypi
```

Pour copier les avis de sécurité sur l'instance hors ligne :

1. Transférez le répertoire de sortie vers l'instance hors ligne.
1. Sur l'instance hors ligne, trouvez la racine du répertoire GitLab Rails, puis copiez les avis de sécurité à leur emplacement et mettez à jour les permissions.

   ```shell
   export GITLAB_RAILS_ROOT_DIR="$(sudo gitlab-rails runner 'puts Rails.root.to_s')"
   echo $GITLAB_RAILS_ROOT_DIR
   sudo mkdir -p "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/malware_advisories"
   sudo rsync --recursive --delete ./malware_advisories/ "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/malware_advisories/"
   sudo chmod -R 755 "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/"
   ```

Le job cron `PackageMetadata::MalwareAdvisoriesSyncWorker` s'exécute toutes les cinq minutes et importe les avis de sécurité lors de sa prochaine exécution. Sur GitLab Self-Managed, le job ajoute un décalage pouvant aller jusqu'à cinq minutes pour répartir la charge entre les instances, de sorte que l'importation peut démarrer jusqu'à dix minutes après la copie des fichiers. Seuls les types de registres de paquets activés dans les [paramètres d'administration](../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync) sont importés ; l'instance peut donc contenir des données pour des registres qu'elle n'importe jamais.

Répétez cette procédure pour mettre à jour les avis de sécurité. `rsync --delete` est requis afin que les archives d'un instantané antérieur ne soient pas importées avec les nouvelles. Réutilisez le même répertoire de sortie à chaque exécution : `rsync --delete` supprime tout registre qui en est absent, y compris les registres qui ont été ignorés parce que leur instantané n'est pas encore publié.

## Télécharger les données de licences v3 {#download-v3-license-data}

{{< details >}}

- Édition : GitLab Ultimate

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/epics/22880) dans GitLab 19.4 avec le feature flag `sync_v3_license_expressions`. Activés par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.
>
> Si vous désactivez l'indicateur, l'instance revient à la disposition v2 et abandonne ses points de contrôle v3. Si vous réactivez l'indicateur, l'instance réimporte les données v3 depuis le début au lieu de reprendre depuis le dernier instantané synchronisé.

La disposition des données de licences v3 utilise des expressions de licences Software Package Data Exchange (SPDX) au lieu d'identifiants de licence uniques. Par exemple, `MIT OR Apache-2.0`.

Le service de distribution de la base de données de métadonnées de paquets distribue les données de licences v3 ; vous les téléchargez donc sur une machine disposant d'un accès à Internet et vous les copiez sur l'instance hors ligne. Il télécharge uniquement ce dont ont besoin les registres que vous avez activés, plutôt que tous les formats que le bucket de licences contient. Il ne nécessite pas `gsutil`. Téléchargez-les avec le script partagé et ses prérequis, décrits dans [Télécharger les données v3 de la base de données de métadonnées de paquets](#download-v3-package-metadata-database-data) :

```shell
./download_pmdb_data.sh ./Gitlab.gitlab-license 19.4.0-ee licenses ./licenses npm pypi
```

Lorsqu'un répertoire `v3` existe sous `vendor/package_metadata/licenses`, l'instance synchronise les licences depuis ce répertoire au lieu du répertoire `v2`. Effectuez l'étape de copie ci-dessous avant l'exécution du job de synchronisation.

Pour copier les données de licences sur l'instance hors ligne :

1. Transférez le répertoire de sortie vers l'instance hors ligne.
1. Sur l'instance hors ligne, trouvez la racine du répertoire GitLab Rails, puis copiez les données de licences à leur emplacement et mettez à jour les permissions.

   ```shell
   export GITLAB_RAILS_ROOT_DIR="$(sudo gitlab-rails runner 'puts Rails.root.to_s')"
   echo $GITLAB_RAILS_ROOT_DIR
   export LICENSES_DIR="$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses"
   sudo rm -rf "$LICENSES_DIR/v3.old" "$LICENSES_DIR/v3.incoming"
   sudo mkdir -p "$LICENSES_DIR/v3" "$LICENSES_DIR/v3.incoming"
   sudo rsync --recursive ./licenses/v3/ "$LICENSES_DIR/v3.incoming/"
   sudo mv "$LICENSES_DIR/v3" "$LICENSES_DIR/v3.old" && \
     sudo mv "$LICENSES_DIR/v3.incoming" "$LICENSES_DIR/v3" && \
     sudo rm -rf "$LICENSES_DIR/v3.old"
   sudo chmod -R 755 "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/"
   ```

   Les commandes écrivent uniquement dans le répertoire `v3`, de sorte qu'un répertoire `v2` existant reste sur le disque, inutilisé.

   L'instance lit les licences depuis le répertoire `v3` dès que ce répertoire existe. Le job de synchronisation s'exécute toutes les cinq minutes ; si vous copiez directement dans `v3`, le job de synchronisation peut lire un répertoire en cours d'écriture et `v3` peut se retrouver manquant ou à moitié écrit. Copiez plutôt dans `v3.incoming` et publiez avec des renommages.

Le job cron `PackageMetadata::LicensesSyncWorker` s'exécute toutes les cinq minutes et importe les données de licences lors de sa prochaine exécution. Comme pour les avis de sécurité, le job importe uniquement les types de registres de paquets activés dans la zone **Admin** ; l'instance peut donc contenir des données pour des registres qu'elle n'importe jamais.

Pour mettre à jour les données de licences, répétez cette procédure. La publication remplace l'intégralité du répertoire `v3` ; un registre exclu d'une exécution ultérieure cesse donc de recevoir des mises à jour. Les données de licences déjà importées pour ce registre restent dans la base de données, et les mises à jour reprennent la prochaine fois que vous l'incluez dans une exécution.

## Version de format des données de licences v3 {#v3-license-data-format-version}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/epics/22880) dans GitLab 19.4.

{{< /history >}}

`v2` et `v3` sont des versions de format de l'export de licences, chacune publiée dans son propre dossier et contenant un type différent de données de licences :

| Version de format | Dossier                                 | Données de licences                                      | Lu par |
|----------------|----------------------------------------|---------------------------------------------------|---------|
| v2             | `licenses/v2/<registry>/`              | Identifiants SPDX uniques, dans des fichiers `.ndjson`.      | GitLab 19.3 et versions antérieures |
| v3             | `licenses/v3/<registry>/full_dataset/` | Expressions de licences SPDX, dans des archives compressées. | GitLab 19.4 et versions ultérieures |

Vous ne choisissez pas la version de format, c'est GitLab qui le fait. Une instance peut contenir les deux dossiers, mais GitLab n'en lit qu'un seul.

Dans GitLab 19.4 et versions ultérieures, GitLab lit v3 lorsque l'indicateur `sync_v3_license_expressions` est activé et qu'un dossier `v3/` existe sous `vendor/package_metadata/licenses`. Lorsque les deux dossiers sont présents, v3 prend la priorité et `v2/` est ignoré. Désactivez l'indicateur pour lire v2 à la place. Les versions antérieures lisent toujours v2.

À propos de la structure de dossiers v3 :

- GitLab organise les données sous `v3/<registry>`, où `<registry>` est un nom tel que `go`, `rubygem` ou `packagist`.
- Chaque dossier de registre contient un dossier `full_dataset/` et, optionnellement, un dossier `deltas/`. `full_dataset/` est un instantané complet, divisé en fragments : un fichier `checkpoint.json` avec l'horodatage de l'instantané, et une archive `.tar.zst` par fragment, nommée d'après l'identifiant du fragment, par exemple `00.tar.zst`. `deltas/` contient les modifications incrémentielles, chaque archive étant nommée d'après l'horodatage Unix qui marque la fin de sa fenêtre.

  ```plaintext
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/full_dataset/checkpoint.json
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/full_dataset/00.tar.zst
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/full_dataset/01.tar.zst
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/full_dataset/...
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/deltas/1757520000.tar.zst
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/deltas/1757606400.tar.zst
  ```

- La première synchronisation d'un registre lit `full_dataset/` et ignore `deltas/`, car un delta ne peut pas remplacer un jeu de données complet. Les synchronisations ultérieures lisent ce qui est plus récent que le point de contrôle, en commençant par le plus ancien.

  > [!warning]
  > Une archive delta ne nomme que la fin de sa fenêtre ; un dossier `deltas/` présentant un écart ressemble donc à un dossier complet, et GitLab ne signale aucune erreur. Copiez l'intégralité du dossier `deltas/` produit par le script de téléchargement plutôt qu'une sélection d'archives.

- Un job de synchronisation s'arrête après une durée fixe ; un registre volumineux nécessite donc plusieurs exécutions. Un instantané reprend fragment par fragment, à chaque synchronisation et pas seulement à la première, de sorte qu'une exécution interrompue relit au maximum un fragment. Une archive delta reprend dans son intégralité ; une archive interrompue est donc relue depuis son début lors de la prochaine exécution. Le découpage des grands deltas en fragments comme le sont les instantanés est suivi dans le [ticket 608196](https://gitlab.com/gitlab-org/gitlab/-/issues/608196).

## Instances installées avec le chart Helm {#instances-installed-with-the-helm-chart}

Ces procédures écrivent dans le répertoire Rails d'une installation de paquet Linux. Les jobs de synchronisation s'exécutent dans Sidekiq. Sur une installation utilisant le chart Helm GitLab, les mêmes fichiers doivent se trouver sur un volume que les pods Sidekiq lisent à l'adresse `/srv/gitlab/vendor/package_metadata`. Un volume monté uniquement sur le pod toolbox n'est pas suffisant. La synchronisation s'exécute toujours dans Sidekiq, ne trouve toujours aucun répertoire et tente toujours le chemin réseau à chaque exécution.

Déclarez le volume dans les valeurs du chart sous `gitlab.sidekiq` :

```yaml
gitlab:
  sidekiq:
    extraVolumes: |
      - name: package-metadata
        persistentVolumeClaim:
          claimName: gitlab-package-metadata
          readOnly: true
    extraVolumeMounts: |
      - name: package-metadata
        mountPath: /srv/gitlab/vendor/package_metadata
        readOnly: true
```

Aucun autre paramètre n'est nécessaire. GitLab sélectionne le chemin hors ligne en fonction de la présence du répertoire. La modification prend effet lors de la prochaine exécution de synchronisation, sans redémarrage ni tâche Rake.

Chaque pod Sidekiq monte la revendication ; donnez donc au volume un mode d'accès qui le permet, tel que `ReadOnlyMany`. GitLab ne fait que lire ces fichiers.

Faites attention à deux erreurs courantes dans les valeurs :

- Écrivez `extraVolumes` et `extraVolumeMounts` en tant que [chaînes de caractères, et non comme des listes YAML](https://docs.gitlab.com/charts/charts/gitlab/sidekiq/). Une liste échoue au rendu avec une erreur de type qui nomme le modèle. Un fichier de valeurs qui place les clés au mauvais niveau échoue silencieusement. Helm ignore la clé qu'il ne reconnaît pas, le Deployment est rendu sans le montage, et la commande réussit. Un rendu réussi n'est pas une preuve. Vérifiez que le montage a bien atteint le Deployment :

  ```shell
  kubectl get deployment -l app=sidekiq -o yaml | grep -c 'vendor/package_metadata'
  ```

  Le chart fait passer ces chaînes de caractères par le moteur de modèles Helm ; échappez donc tout `{{` dans un nom de volume ou un chemin de montage.

- Le montage appartient aux valeurs, et non à `kubectl set env` ou `kubectl patch`. La prochaine exécution de `helm upgrade` l'écrase. Sur un déploiement qui se réconcilie à partir d'une configuration stockée, la prochaine réconciliation remet l'instance sur le chemin réseau. Dans un environnement hors ligne, cela signifie qu'il n'y a aucune donnée de vulnérabilité.

Pour suivre une importation, lisez les séquences enregistrées et les journaux sur les pods Sidekiq plutôt que sur les pods Webservice, comme décrit dans [la résolution des problèmes](#troubleshooting).

## Dépannage {#troubleshooting}

### Données de base de données manquantes {#missing-database-data}

Si des données de licences ou d'avis de sécurité sont absentes de la liste des dépendances, des rapports de vulnérabilités ou des pages de merge requests, il est possible que la base de données ne soit pas synchronisée avec les données d'export.

#### Confirmer les types de registres de paquets activés {#confirm-enabled-package-registry-types}

La synchronisation de `package_metadata` est déclenchée par des jobs cron ([synchronisation des avis de sécurité](https://gitlab.com/gitlab-org/gitlab/-/blob/16-3-stable-ee/config/initializers/1_settings.rb#L864-866) et [synchronisation des licences](https://gitlab.com/gitlab-org/gitlab/-/blob/16-3-stable-ee/config/initializers/1_settings.rb#L855-857)). Seuls les types de registres de paquets activés dans les [paramètres d'administration](../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync) sont importés.

Par exemple, si `maven` est sélectionné mais pas `golang`, vous ne verrez que les avis de sécurité et les informations de licence pour Maven.

#### Confirmer la structure de fichiers correcte {#confirm-correct-file-structure}

La structure de fichiers dans `vendor/package_metadata` doit correspondre au type de registre de paquets activé précédemment. Par exemple, pour synchroniser les données de licences ou d'avis de sécurité `maven`, le répertoire de métadonnées de paquets sous le répertoire Rails doit avoir la structure suivante, où `$GITLAB_RAILS_ROOT_DIR` correspond au résultat de la commande `gitlab-rails runner 'puts Rails.root.to_s'` :

- Pour les licences sur v2 (GitLab 19.3 et versions antérieures) :`$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v2/maven/**/*.ndjson`.
- Pour les licences sur v3 (GitLab 19.4 et versions ultérieures) :`$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/maven/full_dataset/*`. Consultez [la version de format des données de licences v3](#v3-license-data-format-version).
- Pour les avis de sécurité sur v2 :`$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/advisories/v2/maven/**/*.ndjson`.

L'enrichissement CVE n'est pas divisé par type de registre de paquets. Dans GitLab 19.5 et versions ultérieures, GitLab lit une copie du bucket telle quelle, depuis `$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment/v2/cve_enrichment/*/*.ndjson`. Lorsque ce répertoire `cve_enrichment` existe, GitLab ne lit que ce répertoire. Dans GitLab 19.4 et versions antérieures, ou lorsque ce répertoire n'existe pas, les fichiers d'enrichissement CVE doivent se trouver exactement deux niveaux de répertoire en dessous du répertoire de version :

- Pour l'enrichissement CVE : `$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment/v2/*/*.ndjson`.

Dans GitLab 19.4 et versions antérieures, une copie du bucket d'enrichissement CVE telle quelle place les fichiers à un niveau plus profond que requis, et GitLab n'en lit aucun. Pour y remédier, consultez [l'étape d'enrichissement CVE dans la procédure de téléchargement](#download-v2-package-metadata-with-gsutil).

Vous pouvez vérifier si GitLab reconnaît le chemin du fichier dans la [console Rails](../../administration/operations/rails_console.md) :

- Pour les licences : `sudo gitlab-rails runner "puts File.exist?(PackageMetadata::SyncConfiguration::Location::LICENSES_PATH)"`
- Pour les avis de sécurité : `sudo gitlab-rails runner "puts File.exist?(PackageMetadata::SyncConfiguration::Location::ADVISORIES_PATH)"`
- Pour l'enrichissement CVE : `sudo gitlab-rails runner "puts File.exist?(PackageMetadata::SyncConfiguration::Location::CVE_ENRICHMENT_PATH)"`

Si les commandes ci-dessus renvoient `false`, GitLab ne peut pas trouver le chemin de paquet attendu. Tous les dossiers et fichiers du chemin doivent avoir les permissions `755`. Pour mettre à jour les permissions :

`sudo chmod -R 755 $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/`

#### Vérifier les données {#verify-data}

Après l'exécution réussie d'un job de synchronisation, les données dans les tables `pm_` de la base de données doivent être renseignées.

Vous pouvez le confirmer en vérifiant le nombre de paquets existants pour un fournisseur à l'aide de la [console Rails](../../administration/operations/rails_console.md). Par exemple, pour confirmer que les données de licences et d'avis de sécurité Maven ont été chargées, exécutez :

- Pour les licences : `sudo gitlab-rails runner "puts \"Package model has #{PackageMetadata::Package.where(purl_type: 'maven').size} packages\""`
- Pour les avis de sécurité : `sudo gitlab-rails runner "puts \"Advisory model has #{PackageMetadata::AffectedPackage.where(purl_type: 'maven').size} packages\""`

De plus, des données de point de contrôle doivent exister pour le registre de paquets particulier en cours de synchronisation. Pour Maven, par exemple, un point de contrôle doit être créé après une exécution de synchronisation réussie :

- Pour les licences : `sudo gitlab-rails runner "puts \"maven data has been synced up to #{PackageMetadata::Checkpoint.where(data_type: 'licenses', purl_type: 'maven')}\""`
- Pour les avis de sécurité : `sudo gitlab-rails runner "puts \"maven data has been synced up to #{PackageMetadata::Checkpoint.where(data_type: 'advisories', purl_type: 'maven')}\""`

#### Journaux {#logs}

Le fichier [`application_json.log`](../../administration/logs/_index.md#application_jsonlog) permet de vérifier que le job de synchronisation s'est exécuté et s'est déroulé sans erreur. Les événements associés à la synchronisation auront une gravité `DEBUG` et la classe est `PackageMetadata::SyncService`. Exemple : `{"severity":"DEBUG","time":"2026-01-07T02:15:49.618Z","meta.caller_id":"PackageMetadata::AdvisoriesSyncWorker","correlation_id":"43008e30dd708eadbe1ab16ad7fa953f","meta.root_caller_id":"Cronjob","meta.feature_category":"software_composition_analysis","meta.client_id":"ip/","class":"PackageMetadata::SyncService","message":"Evaluating data for advisories:offline//opt/gitlab/embedded/service/gitlab-rails/vendor/package_metadata/advisories/v2/maven/1761761049/0.ndjson"}`

Les journaux [`sidekiq`](../../administration/logs/_index.md#sidekiq-logs) indiquent si des erreurs se sont produites pendant le job de synchronisation. Les événements consignés pour la synchronisation mentionneront les classes pertinentes :

- Pour les licences : `PackageMetadata::LicensesSyncWorker`
- Pour les avis de sécurité : `PackageMetadata::AdvisoriesSyncWorker`

### Données de licences v3 manquantes {#missing-v3-license-data}

Si des données de licences sont manquantes après les avoir copiées sur l'instance, le job de synchronisation n'a pas trouvé le répertoire ou n'a rien trouvé de nouveau à importer. Les deux résultats sont silencieux ; passez donc en revue les vérifications suivantes au lieu de chercher une erreur.

Avant de commencer :

- Suivez les conseils de résolution des problèmes relatifs aux [données de base de données manquantes](#missing-database-data), en vérifiant notamment les types de registres de paquets activés et la structure de fichiers pour les licences.
- Confirmez la structure de fichiers de licences v3. Elle doit correspondre à la [structure de fichiers des avis de logiciels malveillants](#confirm-the-malware-advisory-file-structure).

#### Vérifier les données de licences v3 {#verify-v3-license-data}

Les expressions sont stockées dans les enregistrements de licences. Pour vérifier votre instantané v3 synchronisé, recherchez au moins une licence avec une expression. Vous pouvez le confirmer dans la console Rails :

- `sudo gitlab-rails runner "puts \"#{PackageMetadata::License.where.not(spdx_expression: nil).count} licenses have an expression\""`

Si des paquets et des points de contrôle existent mais qu'aucune licence ne possède d'expression, l'instance a synchronisé la disposition v2 au lieu de v3. Vérifiez que les données sur le disque se trouvent sous `v3/`.

Un instantané n'est importé que s'il est plus récent que le point de contrôle enregistré ; copier le même instantané une deuxième fois n'a donc aucun effet. Pour obtenir des données de licences plus récentes, relancez le script de téléchargement.

### Données d'avis de logiciels malveillants manquantes {#missing-malware-advisory-data}

Si des avis de logiciels malveillants sont manquants après les avoir copiés sur l'instance, le job de synchronisation n'a pas trouvé le répertoire ou n'a rien trouvé de nouveau à importer. Les deux résultats sont silencieux ; passez donc en revue les vérifications suivantes plutôt que de chercher une erreur.

#### Confirmer les types de registres de paquets activés pour les avis de logiciels malveillants {#confirm-enabled-package-registry-types-for-malware-advisories}

Seuls les types de registres de paquets activés dans les [paramètres d'administration](../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync) sont importés. Un registre que vous avez copié mais pas activé n'est jamais lu, et rien n'est consigné.

#### Confirmer que GitLab détecte le répertoire hors ligne {#confirm-gitlab-detects-the-offline-directory}

GitLab lit les avis de logiciels malveillants depuis le disque lorsque le répertoire vendor existe, et depuis le service de distribution lorsqu'il n'existe pas. Vous pouvez vérifier si GitLab reconnaît le chemin du fichier dans la [console Rails](../../administration/operations/rails_console.md) :

- `sudo gitlab-rails runner "puts File.exist?(PackageMetadata::SyncConfiguration::Location::MALWARE_ADVISORIES_PATH)"`

Si la commande renvoie `false`, GitLab ne peut pas trouver le chemin attendu. Tous les dossiers et fichiers du chemin doivent avoir les permissions `755`. Dans les installations Kubernetes, exécutez la commande dans un pod qui monte le même volume que Sidekiq, sinon le résultat ne reflète pas ce que lit le job de synchronisation.

#### Confirmer la structure de fichiers des avis de logiciels malveillants {#confirm-the-malware-advisory-file-structure}

Les répertoires sont nommés d'après l'identifiant du registre de paquets plutôt que le type de paquet. Ces identifiants ne sont pas toujours identiques : les avis `gem` sont stockés sous `rubygem`, `golang` sous `go` et `composer` sous `packagist`. Un répertoire nommé d'après le type de paquet est ignoré, et aucune erreur n'est consignée.

Chaque répertoire `full_dataset` doit également contenir un fichier `checkpoint.json`. GitLab ignore un répertoire sans point de contrôle, ce qui empêche qu'un téléchargement interrompu soit importé.

#### Vérifier les données d'avis de logiciels malveillants {#verify-malware-advisory-data}

Après l'exécution réussie d'un job de synchronisation, les avis de logiciels malveillants doivent être renseignés. Vous pouvez le confirmer en comptant les avis de sécurité dans la [console Rails](../../administration/operations/rails_console.md) :

- `sudo gitlab-rails runner "puts \"Malware advisory model has #{PackageMetadata::MalwareAdvisory.count} advisories\""`

Des données de point de contrôle doivent également exister pour les registres de paquets que vous avez copiés :

- `sudo gitlab-rails runner "puts PackageMetadata::Checkpoint.where(data_type: 'malware_advisories').pluck(:purl_type, :sequence).to_h"`

Un instantané n'est importé que s'il est plus récent que le point de contrôle enregistré ; copier le même instantané une deuxième fois n'a donc aucun effet.

#### Journaux des avis de logiciels malveillants {#malware-advisory-logs}

Les événements associés à la synchronisation des avis de logiciels malveillants sont consignés dans [`application_json.log`](../../administration/logs/_index.md#application_jsonlog) avec la gravité `INFO`. La classe est `PackageMetadata::MalwareAdvisorySyncService` pour la synchronisation elle-même, et `PackageMetadata::MalwareAdvisoryIngestionService` pour l'importation. La synchronisation s'exécute dans Sidekiq ; dans les installations Kubernetes, ces événements se trouvent donc sur les pods Sidekiq sous la clé `subcomponent="application_json"`, et non sur les pods Webservice.

Les journaux [`sidekiq`](../../administration/logs/_index.md#sidekiq-logs) affichent toutes les erreurs survenues, consignées pour la classe `PackageMetadata::MalwareAdvisoriesSyncWorker`.

Chaque registre consigne un événement `started` et un événement `completed` par exécution. Un événement `completed` avec `files_ingested: 0` signifie que l'exécution n'a rien trouvé à importer. Le champ `storage_type` de cet événement vous indique dans quel cas vous vous trouvez : `offline` signifie que GitLab a lu le répertoire vendor, et `pds` signifie qu'il n'a pas trouvé le répertoire et a essayé le service de distribution à la place. Sur Kubernetes, ce champ est plus fiable que la vérification `File.exist?` précédente, car il provient du processus qui exécute la synchronisation.

Si aucun événement `PackageMetadata::MalwareAdvisorySyncService` n'apparaît, recherchez un événement `PackageMetadata::MalwareAdvisoriesSyncWorker` avec la gravité `DEBUG`. Il indique la raison pour laquelle l'exécution n'a pas démarré, par exemple ni la licence `dependency_scanning` ni le pare-feu des dépendances ne sont disponibles.

Une première importation d'un registre volumineux peut prendre plusieurs minutes, et le cron se déclenche à nouveau toutes les cinq minutes pendant ce temps. Chaque exécution qui se chevauche consigne `Cannot obtain an exclusive lease. There must be another instance already in execution.` dans `application_json.log` avec la gravité `ERROR`, puis se termine. Le bail est ce qui empêche deux synchronisations de s'exécuter simultanément ; ces événements sont donc attendus lors d'une importation longue et ne signifient pas que la synchronisation a échoué.
