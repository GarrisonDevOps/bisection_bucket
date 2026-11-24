#!/usr/bin/env bash
# Vendored from https://gitlab.com/gitlab-com/gl-infra/common-template-copier
# Consider contributing upstream when updating this file

# See the README.md for details of how this script works

set -euo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export LANG=C LC_ALL=C

generate() {
  sort "${ROOT_DIR}/.tool-versions" |
    awk '
    BEGIN {
      print "# DO NOT MANUALLY EDIT; Run ./scripts/update-asdf-version-variables.sh to update this";
      print "variables:"
    }
    {
      if (!/^#/ && $1 != "" && $2 != "system") {
        gsub("-", "_", $1);
        print "    GL_ASDF_" toupper($1) "_VERSION: \"" $2 "\""
      }
    }
    '
}

generate >"${ROOT_DIR}/.gitlab-ci-asdf-versions.yml"
