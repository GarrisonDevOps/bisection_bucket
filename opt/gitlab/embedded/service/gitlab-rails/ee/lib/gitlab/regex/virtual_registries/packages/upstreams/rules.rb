# frozen_string_literal: true

module Gitlab
  module Regex
    module VirtualRegistries
      module Packages
        module Upstreams
          module Rules
            # Regex for Maven app group wildcard patterns in upstream allow/deny rules.
            # Accepts group IDs with optional wildcards, including standalone '*' to match all groups.
            # Examples:
            #   - '*' (matches all groups)
            #   - 'com.example.*' (matches groups with wildcard at end)
            #   - '*.example.com' (matches groups with wildcard at start)
            #   - '*.example.*' (matches groups with wildcard at start and end)
            def self.maven_app_group_wildcard_pattern_regex
              @maven_app_group_wildcard_pattern_regex ||=
                %r{\A(?:\*|\*?#{regex_without_anchors(::Gitlab::Regex.maven_app_group_regex)}\*?)\z}
            end

            # Regex for Maven app name wildcard patterns in upstream allow/deny rules.
            # Accepts app names with optional wildcards, including standalone '*' to match all apps.
            # Examples:
            #   - '*' (matches all apps)
            #   - 'artifact-*' (matches apps with wildcard at end)
            #   - '*-artifact' (matches apps with wildcard at start)
            #   - '*-artifact-*' (matches apps with wildcard at start and end)
            def self.maven_app_name_wildcard_pattern_regex
              @maven_app_name_wildcard_pattern_regex ||=
                %r{\A(?:\*|\*?#{regex_without_anchors(::Gitlab::Regex.maven_app_name_regex)}\*?)\z}
            end

            # Regex for Maven version wildcard patterns in upstream allow/deny rules.
            # Accepts versions with optional wildcards, including standalone '*' to match all versions.
            # Wildcards can appear at the start, end, or between version segments.
            # Examples:
            #   - '*' (matches all versions)
            #   - '1.0.*' (matches versions with wildcard at end)
            #   - '*-SNAPSHOT' (matches versions with wildcard at start)
            #   - '*-SNAPSHOT-*' (matches versions with wildcard at start and end)
            #   - '1.*.*' (matches versions starting with major, with wildcards for minor and patch)
            def self.maven_version_wildcard_pattern_regex
              @maven_version_wildcard_pattern_regex ||=
                %r{\A(?:\*|\*?#{regex_without_anchors(::Gitlab::Regex.maven_version_regex)}(?:\.\*(?!\*))*\*?)\z}
            end

            # Extracts the pattern content from a regex source by removing the leading \A and trailing \z anchors.
            # This allows embedding the pattern within a larger regex while maintaining the original pattern logic.
            def self.regex_without_anchors(regex)
              regex.source[2..-3]
            end
            private_class_method :regex_without_anchors
          end
        end
      end
    end
  end
end
