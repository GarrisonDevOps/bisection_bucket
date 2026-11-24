#!/bin/sh
# Turns the current directory, a gitlab-org/gitlab checkout, into the FOSS tree
# by removing the paths listed in .gitlab/ee-only-paths.txt.
# POSIX sh on purpose: as-if-foss jobs run it in images without Bash.

set -eu

list=".gitlab/ee-only-paths.txt"

fail() {
  echo "ERROR: $list$1" >&2
  exit 1
}

if [ ! -e "$list" ] && [ ! -L "$list" ]; then
  fail " not found"
elif [ ! -f "$list" ] || [ ! -r "$list" ]; then
  fail " is not a readable regular file"
fi

# Calls "$1 <entry>" for each entry of the list, with $lineno set.
each_entry() {
  lineno=0
  while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    case "$line" in
      '' | '#'*) continue ;;
    esac
    "$1" "$line"
  done < "$list"
}

# Prints why the path "$1" is invalid, or nothing if it is valid.
path_problem() {
  case "$1" in
    /*) echo 'leading /' ;;
    */) echo 'trailing /' ;;
    *//*) echo 'empty path segment' ;;
    *)
      case "/$1/" in
        */./*) echo '. path segment' ;;
        */../*) echo '.. path segment' ;;
        /.git/*) echo 'first path segment is .git' ;;
      esac
      ;;
  esac
}

# Calls "$2 <match>" for each existing path matching the glob "$1".
each_match() {
  # Unquoted so the glob expands; an empty IFS stops word splitting.
  IFS=
  for path in $1; do
    if [ -e "$path" ] || [ -L "$path" ]; then
      "$2" "$path"
    fi
  done
  unset IFS
}

# Text checks cannot catch globs such as `.g?t` or `.*`, so check matches too.
check_match() {
  problem=$(path_problem "$1")
  [ -z "$problem" ] || fail ":$lineno: entry '$entry' matches '$1': $problem"
}

entries=0
validate() {
  entry=$1
  entries=$((entries + 1))
  problem=$(path_problem "$entry")
  # A `#` in an entry is most likely an attempted trailing comment.
  if [ -z "$problem" ]; then
    case "$entry" in
      *'#'*) problem='# is only allowed at the start of a comment line' ;;
    esac
  fi
  [ -z "$problem" ] || fail ":$lineno: invalid entry '$entry': $problem"
  each_match "$entry" check_match
}

remove_match() {
  echo "Removing $1"
  rm -rf -- "$1"
}

remove() {
  each_match "$1" remove_match
}

# Validate every entry before removing anything.
each_entry validate
[ "$entries" -gt 0 ] || fail " has no entries"
each_entry remove
