# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # Follows Dependabot's PrNamePrefixer rules for Conventional Commits histories, so our
    # commits match what Dependabot would write. Its ESLint, gitmoji and custom-prefix
    # fallbacks are left out: those histories have no `build` type, so they keep the plain title.
    class CommitConvention
      Style = Struct.new(:type, :capitalize, keyword_init: true)

      SAMPLE_SIZE = 20
      # The service account's own commits are dropped from the sample, and in a project
      # with many remediations they can fill all of the latest SAMPLE_SIZE.
      FETCH_LIMIT = 50
      MIN_CONVENTIONAL_RATIO = 0.3
      CONVENTIONAL_TITLE =
        /\A(?<type>build|chore|ci|docs|feat|fix|perf|refactor|style|test)(?:\([^)]*\))?!?: (?<subject>\S)/i

      # Our own conventional titles, so an open MR keeps the style it was created with.
      OWN_TITLE = /\A(?<type>[Bb]uild|[Cc]hore)\(deps\): \[(?<security>[Ss])ecurity\] /

      def self.detect(project, exclude_email:)
        new(project, exclude_email: exclude_email).detect
      end

      # @return [Style, nil] nil when the title is not one of our conventional titles
      def self.from_title(title)
        match = OWN_TITLE.match(title.to_s)
        return unless match

        Style.new(type: match[:type], capitalize: match[:security] == 'S')
      end

      def initialize(project, exclude_email:)
        @project = project
        @exclude_email = exclude_email
      end

      # @return [Style, nil] nil when the default branch does not follow Conventional Commits
      def detect
        titles = recent_titles
        return if titles.empty?

        matches = titles.filter_map { |title| CONVENTIONAL_TITLE.match(title) }
        return if matches.empty? || matches.size < titles.size * MIN_CONVENTIONAL_RATIO

        types = matches.map { |match| match[:type].downcase }
        type = types.include?('chore') && types.exclude?('build') ? 'chore' : 'build'
        capitalized_types = matches.count { |match| match[:type].match?(/\A[A-Z]/) }
        capitalized = matches.count { |match| match[:subject].match?(/\A[A-Z]/) }

        Style.new(
          type: capitalized_types > matches.size / 2.0 ? type.capitalize : type,
          capitalize: capitalized > matches.size / 2.0
        )
      rescue StandardError => e
        # Only formatting depends on this, so a failed read must not stop the remediation.
        Gitlab::ErrorTracking.track_exception(e, project_id: project.id)
        nil
      end

      private

      attr_reader :project, :exclude_email

      def recent_titles
        default_branch = project.default_branch
        return [] unless default_branch

        project.repository
          .commits(default_branch, limit: FETCH_LIMIT, skip_merges: true)
          .reject { |commit| commit.author_email == exclude_email }
          .first(SAMPLE_SIZE)
          .map(&:title)
      end
    end
  end
end
