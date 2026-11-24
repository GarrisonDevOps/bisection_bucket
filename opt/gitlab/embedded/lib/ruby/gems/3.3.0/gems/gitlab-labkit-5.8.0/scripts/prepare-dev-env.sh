#!/usr/bin/env bash
# Vendored from https://gitlab.com/gitlab-com/gl-infra/common-template-copier
# Consider contributing upstream when updating this file

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------
# This script will prepare your development environment
# while working on this project. Run it after cloning this
# project.
#
# It's recommended that you review
# https://gitlab.com/gitlab-com/gl-infra/common-ci-tasks/-/blob/main/docs/developer-setup.md
# first.
# ---------------------------------------------------------

cd "$(dirname "${BASH_SOURCE[0]}")/.."

warn() {
  echo >&2 -e "${1-}"
  echo >&2 -e "Recommended reading: https://gitlab.com/gitlab-com/gl-infra/common-ci-tasks/-/blob/main/docs/developer-setup.md"
}

# `mise plugins update` contacts GitHub for every registered plugin: slow, and
# it adds up when many vendored copies of this script run across many projects
# on the same machine. Throttle it to once a day using a stamp file in the
# user's cache directory, deliberately outside the project so that the throttle
# is shared by every project that vendors this script.
mise_plugins_update() {
  local stamp_dir="${XDG_CACHE_HOME:-${HOME:-}/.cache}/common-template-copier"
  local stamp_file="${stamp_dir}/mise-plugins-update"

  # `find -mtime -1` rather than `stat`, which is spelled differently on
  # GNU/BSD. It prints nothing when the stamp is missing or over a day old.
  if [[ -z ${FORCE_MISE_PLUGINS_UPDATE-} ]] && [[ -n $(find "$stamp_file" -mtime -1 2>/dev/null) ]]; then
    echo >&2 "skipping 'mise plugins update' (ran in the last 24h; set FORCE_MISE_PLUGINS_UPDATE=1 to force)"
    return 0
  fi

  mise plugins update -q

  # Best effort: a machine without a writable cache dir just updates every time.
  mkdir -p "$stamp_dir" && touch "$stamp_file" || true
}

if command -v mise >/dev/null; then
  echo >&2 -e "mise installed..."
elif command -v rtx >/dev/null; then
  warn "⚠️ 2024-01-02: 'rtx' has changed to 'mise'; please replace 'rtx' with 'mise'"
  exit 1
elif [[ -n ${ASDF_DIR-} ]]; then
  warn "⚠️ 2024-08-07: 'asdf' is no longer supported; please uninstall and replace with 'mise'"
  exit 1
else
  warn "mise is not installed."
  exit 1
fi

# Do some validation to ensure that the environment is not misconfigured, as this may
# save a bunch of debugging effort down the line.

# Detect Rosetta 2
if [[ $(uname -m) == "arm64" ]] && [[ $(uname -p) == "x86_64" ]]; then
  echo "This shell is running in Rosetta emulating x86_64. Please use native mode Apple Silicon." >&2
  echo "For help visit https://gitlab.com/gitlab-com/gl-infra/common-ci-tasks/-/blob/main/docs/developer-setup.md" >&2
  exit 1
fi

# Detect ancient versions of bash
if ((BASH_VERSINFO[0] < 4)); then
  echo "You're running bash < v4.0.0. Please upgrade to a newer version." >&2
  echo "For help visit https://gitlab.com/gitlab-com/gl-infra/common-ci-tasks/-/blob/main/docs/developer-setup.md" >&2
  exit 1
fi

# install mise/asdf dependencies
echo "installing required plugins with mise install.."
mise trust --yes
mise_plugins_update
mise install

# set PROMPT_COMMAND to empty value for mise if unset
: "${PROMPT_COMMAND:=}"
eval "$(mise activate bash)"

# pre-commit is optional
if command -v pre-commit &>/dev/null; then
  echo "running pre-commit install..."
  pre-commit install
  pre-commit install-hooks
  pre-commit install --hook-type commit-msg
else
  warn "pre-commit is not installed. Skipping."
fi
