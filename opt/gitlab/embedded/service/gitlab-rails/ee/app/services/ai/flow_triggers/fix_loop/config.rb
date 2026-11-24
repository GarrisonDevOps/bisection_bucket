# frozen_string_literal: true

module Ai
  module FlowTriggers
    module FixLoop
      # The `review` key of .gitlab-dap-factory.yml on the default branch. Without the file, the key, or a value,
      # the defaults apply. An invalid key starts no fix run, so a typo never runs a loop with a limit nobody set.
      class Config
        PATH = '.gitlab-dap-factory.yml'
        DEFAULT_MAX_FIX_RUNS = 3
        MAX_FIX_RUNS = (1..10)
        KEYS = %w[label reviewer max_fix_runs].freeze
        # The note to the author quotes the unknown keys, so it names only plain ones.
        PLAIN_KEY = /\A[\w.-]{1,64}\z/

        # `reviewer` is the username of the `reviewer` key. It is nil without the key, and with an error in it.
        attr_reader :label, :reviewer, :max_fix_runs, :errors

        def self.for_project(project)
          ref = project.default_branch

          new(ref && project.repository.blob_data_at(ref, PATH))
        end

        # `content` is nil when the file does not exist.
        def initialize(content)
          @errors = []
          settings = review_settings(content)
          # An unreadable `review` key names no label and no reviewer, so every verdict gets the note about it.
          return unless settings

          @label = read_label(settings['label'])
          @reviewer = read_reviewer(settings['reviewer'])
          @reviewer_known = settings['reviewer'].nil? || reviewer.present?
          @max_fix_runs = read_max_fix_runs(settings['max_fix_runs'])
        end

        def valid?
          errors.empty?
        end

        # Without a `reviewer` key, the reviewer is the Duo Code Review bot. Its username differs between instances,
        # for example with the suffix of an organization. With an error in the key, the reviewer is unknown, so no
        # verdict counts as the verdict of another reviewer.
        def other_reviewer?(user)
          return false unless @reviewer_known

          reviewer ? !user.username.casecmp?(reviewer) : !user.duo_code_review_bot?
        end

        private

        # Returns nil when the file or its `review` key cannot be read.
        def review_settings(content)
          return {} if content.blank?

          loader = ::Gitlab::Config::Loader::Yaml.new(content)
          # A file with only comments has no document.
          return {} if loader.blank?

          review = loader.load_raw!['review']
          return {} if review.nil?

          unless review.is_a?(Hash)
            errors << s_('AiFlowTriggers|`review` must be a mapping.')
            return
          end

          check_unknown_keys(review)
          review
        rescue ::Gitlab::Config::Loader::FormatError
          errors << s_('AiFlowTriggers|The file is not a valid YAML mapping.')
          nil
        end

        def check_unknown_keys(review)
          unknown = review.keys.map(&:to_s) - KEYS
          return if unknown.empty?

          named = unknown.grep(PLAIN_KEY).map { |key| "`#{key}`" }
          errors << if named.size == unknown.size
                      format(s_('AiFlowTriggers|Unknown keys: %{keys}.'), keys: named.join(', '))
                    else
                      s_('AiFlowTriggers|`review` has unknown keys.')
                    end
        end

        def read_label(value)
          return if value.nil?
          return value.strip.presence if value.is_a?(String)

          errors << s_('AiFlowTriggers|`label` must be a string.')
          nil
        end

        def read_reviewer(value)
          return if value.nil?

          username = value.strip.delete_prefix('@').strip if value.is_a?(String)
          return username if username.present?

          errors << s_('AiFlowTriggers|`reviewer` must be a username.')
          nil
        end

        def read_max_fix_runs(value)
          return DEFAULT_MAX_FIX_RUNS if value.nil?
          return value if value.is_a?(Integer) && MAX_FIX_RUNS.cover?(value)

          errors << format(s_('AiFlowTriggers|`max_fix_runs` must be a number from %{min} to %{max}.'),
            min: MAX_FIX_RUNS.min, max: MAX_FIX_RUNS.max)
          nil
        end
      end
    end
  end
end
