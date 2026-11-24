# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    module MergeRequestTitle
      # The git convention for a commit subject, which linters such as Danger enforce.
      # A squash merge commits the title, so the title has to fit.
      MAX_CONVENTIONAL_LENGTH = 72

      # Matches both the plain and the conventional format, since closed MRs keep whichever
      # title they were created with. Grouped titles ("Security: Update N dependencies")
      # intentionally don't match: version-aware dismissal for grouped updates is out of
      # scope for now.
      SINGLE_DEPENDENCY_REGEX = /
        \A(?:Security:\ Update|\w+\(deps\):\ \[security\]\ update)
        \ (?<name>.+?)(?:\ from\ \S+)?\ to\ (?<version>\S+)\z
      /ix

      # @param style [CommitConvention::Style, nil] nil keeps the plain format
      def self.build(dependencies, style: nil)
        return build_conventional(dependencies, style) if style

        if dependencies.size == 1
          dep = dependencies.first
          "Security: Update #{dep.name} from #{dep.previous_version} to #{dep.version}"
        else
          "Security: Update #{dependencies.size} dependencies"
        end
      end

      def self.parse_single_dependency(title)
        SINGLE_DEPENDENCY_REGEX.match(title)
      end

      def self.build_conventional(dependencies, style)
        prefix = "#{style.type}(deps): #{style.capitalize ? '[Security] Update' : '[security] update'}"

        return "#{prefix} #{dependencies.size} dependencies" unless dependencies.size == 1

        dep = dependencies.first
        title = "#{prefix} #{dep.name} from #{dep.previous_version} to #{dep.version}"
        return title if title.length <= MAX_CONVENTIONAL_LENGTH

        # A name too long even for this overflows: truncating it would lose the
        # dismissal match, which parses the full name back out of the title.
        "#{prefix} #{dep.name} to #{dep.version}"
      end
      private_class_method :build_conventional
    end
  end
end
