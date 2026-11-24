# frozen_string_literal: true

module Quality
  class TestLevel
    UnknownTestLevelError = Class.new(StandardError)

    # The CE and EE prefixes also cover the same tree inside every
    # domains/<name> root. Domains have no JH half, so jh/ gets no copy.
    DOMAINS_PREFIX = 'domains/*/'
    DOMAIN_CODE_PREFIXES = ['', 'ee/'].freeze
    # Used to split selected specs between the FOSS and EE jobs.
    FOSS_SPEC_PATH = %r{\A(?:domains/[^/]+/)?spec/}
    EE_SPEC_PATH = %r{\A(?:domains/[^/]+/)?ee/spec/}

    TEST_LEVEL_FOLDERS = {
      migration: %w[
        migrations
      ],
      background_migration: %w[
        lib/gitlab/background_migration
        lib/ee/gitlab/background_migration
      ],
      frontend_fixture: %w[
        frontend/fixtures
      ],
      # Unit is split into unit_a and unit_b so each maps to a CI job group under the
      # `parallel:` max of 50. unit_b holds the two heaviest folders (services, models).
      # unit_a and unit_b must stay disjoint, otherwise a folder runs in both CI job groups.
      unit_b: %w[
        models
        services
      ],
      unit_a: %w[
        active_context
        bin
        cells
        channels
        components
        config
        constraints
        contracts
        db
        dependencies
        elastic
        elastic_integration
        events
        experiments
        facades
        factories
        factories_specs
        finders
        frontend
        graphql
        haml_lint
        helpers
        initializers
        keeps
        lib
        metrics_server
        policies
        presenters
        rack_servers
        replicators
        routing
        rubocop
        scripts
        serializers
        sidekiq
        sidekiq_cluster
        spam
        support_specs
        tasks
        uploaders
        validators
        views
        workers
        tooling
        dot_gitlab_ci
      ], # ^ tooling and dot_gitlab_ci might be worth to move to another level
      integration: %w[
        commands
        controllers
        mailers
        requests
      ],
      system: ['features']
    }.freeze

    attr_reader :prefixes

    def initialize(prefixes = nil)
      @prefixes = Array(prefixes).flat_map do |prefix|
        DOMAIN_CODE_PREFIXES.include?(prefix) ? [prefix, "#{DOMAINS_PREFIX}#{prefix}"] : [prefix]
      end
      @patterns = {}
      @regexps = {}
    end

    def pattern(level)
      @patterns[level] ||= "#{prefixes_for_pattern}spec/#{folders_pattern(level)}{,/**/}*#{suffix(level)}".freeze
    end

    def regexp(level, start_with = false)
      @regexps[level] ||= Regexp.new("#{'^' if start_with}#{prefixes_for_regex}spec/#{folders_regex(level)}").freeze
    end

    def level_for(file_path)
      case file_path
      # Detect background migration first since some are under
      #     spec/lib/gitlab/background_migration
      # and tests under spec/lib are unit by default
      when regexp(:background_migration)
        :background_migration
      when regexp(:migration)
        :migration
      # Detect frontend fixture before matching other unit tests
      when regexp(:frontend_fixture)
        :frontend_fixture
      # unit_a/unit_b is a CI-only split for job sizing; detection returns the
      # single :unit level so consumers of example metadata stay split-agnostic.
      when regexp(:unit)
        :unit
      when regexp(:integration)
        :integration
      when regexp(:system)
        :system
      else
        raise UnknownTestLevelError, "Test level for #{file_path} couldn't be set. Please rename the file properly or change the test level detection regexes in #{__FILE__}."
      end
    end

    private

    def prefixes_for_pattern
      return '' if prefixes.empty?

      "{#{prefixes.join(',')}}"
    end

    def prefixes_for_regex
      return '' if prefixes.empty?

      regex_prefix = prefixes.map { |prefix| Regexp.escape(prefix).gsub('\*', '[^/]+') }.join('|')

      "(#{regex_prefix})"
    end

    def suffix(level)
      case level
      when :frontend_fixture
        ".rb"
      else
        "_spec.rb"
      end
    end

    # :unit is a virtual level covering both unit_a and unit_b, kept so callers that
    # want every unit spec (e.g. the `spec:unit` rake task) don't need to know about
    # the CI-only split.
    def folders_for(level)
      return TEST_LEVEL_FOLDERS.fetch(level) unless level == :unit

      TEST_LEVEL_FOLDERS.fetch(:unit_a) + TEST_LEVEL_FOLDERS.fetch(:unit_b)
    end

    def folders_pattern(level)
      case level
      when :all
        '**'
      else
        "{#{folders_for(level).join(',')}}"
      end
    end

    def folders_regex(level)
      case level
      when :all
        ''
      else
        "(#{folders_for(level).join('|')})/"
      end
    end
  end
end
