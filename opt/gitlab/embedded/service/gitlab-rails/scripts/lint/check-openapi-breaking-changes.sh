#!/bin/sh
# Reports breaking changes in the REST API spec between two commits, using the oasdiff policy
# in doc/api/openapi/. Needs only git, yq 4 and oasdiff, so components outside Rails can reuse it.
#
# Usage: scripts/lint/check-openapi-breaking-changes.sh <base> [<head>]
# <head> defaults to HEAD. The policy comes from the working tree, so `<merge>^1 <merge>` replays a past merge.
# Exits 1 when a finding reaches the policy's fail-on level, 2 when the check could not run, and 0 otherwise.

set -eu

spec="doc/api/openapi/openapi_v3.yaml"
policy_dir="doc/api/openapi"

cannot_run() {
  echo "The breaking-change check could not run: $1" >&2
  exit 2
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  cannot_run "usage: $0 <base> [<head>]"
fi
base="$1"
head="${2:-HEAD}"

for tool in git yq oasdiff; do
  command -v "${tool}" > /dev/null || cannot_run "${tool} is not installed."
done

root="$(git rev-parse --show-toplevel)" || cannot_run "not in a git repository."
cd "${root}" || cannot_run "could not change to ${root}."

for rev in "${base}" "${head}"; do
  git rev-parse --verify --quiet "${rev}^{commit}" > /dev/null ||
    cannot_run "commit ${rev} is not in this clone. Fetch it first."
done

if ! git cat-file -e "${base}:${spec}" 2> /dev/null; then
  echo "${spec} does not exist at ${base}, so there is nothing to compare."
  exit 0
fi

git cat-file -e "${head}:${spec}" 2> /dev/null || cannot_run "${spec} does not exist at ${head}."

if [ "$(git rev-parse "${base}:${spec}")" = "$(git rev-parse "${head}:${spec}")" ]; then
  echo "${spec} is the same at ${base} and ${head}."
  exit 0
fi

tmp="$(mktemp -d)" || cannot_run "could not create a temporary directory."
trap 'rm -rf "${tmp}"' EXIT

# Map both specs, or every operation with a lifecycle reports api-stability-decreased. Write JSON:
# yq's YAML output drops the indentation indicator of block scalars such as `pattern: |2-`.
map_lifecycle() {
  git show "$1:${spec}" > "${tmp}/$2.yaml" || cannot_run "git could not read ${spec} at $1."
  yq --output-format=json --from-file "${root}/${policy_dir}/oasdiff_stability_level.yq" "${tmp}/$2.yaml" > "${tmp}/$2.json" ||
    cannot_run "yq could not map the lifecycle in the $2 spec."
}

map_lifecycle "${base}" base
map_lifecycle "${head}" head

echo "Comparing ${spec} at $(git rev-parse --short "${base}") (base) with $(git rev-parse --short "${head}") (head)."
echo

# Run from the temporary directory so that findings name base.json or head.json, not a temporary path.
status=0
(cd "${tmp}" && oasdiff breaking base.json head.json --config "${root}/${policy_dir}/oasdiff.yaml" --format text) \
  > "${tmp}/findings.txt" 2>&1 || status=$?

cat "${tmp}/findings.txt"

case "${status}" in
  0 | 1) ;;
  *) cannot_run "oasdiff exited with ${status}." ;;
esac

tab="$(printf '\t')"
count() {
  grep -c "^$1${tab}\[" "${tmp}/findings.txt" || true
}

if [ "${status}" -eq 1 ]; then
  echo
  echo "Findings by level and check:"
  grep -E "^(error|warning|info)${tab}\[" "${tmp}/findings.txt" | sed "s/^\([a-z]*\)${tab}\[\([^]]*\)\].*/\1 \2/" | sort | uniq -c | sort -rn
  echo
  echo "Each finding names the route, the change and the oasdiff check in brackets."
  echo "${policy_dir}/oasdiff.yaml gives the reason for each check's level. To avoid a breaking change, see"
  echo "https://docs.gitlab.com/development/api_styleguide/#what-to-do-instead-of-a-breaking-change."
fi

echo
echo "Breaking-change findings: $(count error) error, $(count warning) warning, $(count info) info."

exit "${status}"
