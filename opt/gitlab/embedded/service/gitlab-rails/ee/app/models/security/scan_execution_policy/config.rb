# frozen_string_literal: true

# This class is the object representation of a single entry in the policy.yml
module Security
  module ScanExecutionPolicy
    class Config
      include ::Security::PolicyCiSkippable
      include ::Security::PolicyNoPipeline

      DEFAULT_SKIP_CI_STRATEGY = { allowed: true }.freeze
      DEFAULT_NO_PIPELINE_STRATEGY = { allowed: true }.freeze

      # Preconfigured scan defaults that only a policy may override. Group and
      # project CI/CD variables cannot change them, so every enforced scan
      # denylists these keys even when the policy action doesn't declare them.
      SCAN_VARIABLES_WITH_RESTRICTED_VARIABLES = {
        secret_detection: {
          'SECRET_DETECTION_HISTORIC_SCAN' => 'false',
          'SECRET_DETECTION_EXCLUDED_PATHS' => ''
        },
        dependency_scanning: {
          'DS_EXCLUDED_PATHS' => '**/spec,**/test,**/tests,**/tmp,**/node_modules,**/.bundle,**/vendor,**/.git',
          'DS_EXCLUDED_ANALYZERS' => ''
        },
        sast: {
          'DEFAULT_SAST_EXCLUDED_PATHS' => 'spec, test, tests, tmp',
          'SAST_EXCLUDED_PATHS' => '$DEFAULT_SAST_EXCLUDED_PATHS',
          'SAST_EXCLUDED_ANALYZERS' => '',
          'ADVANCED_SAST_PARTIAL_SCAN' => 'false'
        },
        sast_iac: {
          'SAST_EXCLUDED_PATHS' => 'spec, test, tests, tmp',
          'SAST_EXCLUDED_ANALYZERS' => ''
        }
      }.freeze

      attr_reader :actions, :configuration, :project, :skip_ci_strategy, :no_pipeline_strategy, :name

      def initialize(policy:, project:, configuration: nil)
        @configuration = configuration
        @project = project
        @skip_ci_strategy = policy[:skip_ci].presence || DEFAULT_SKIP_CI_STRATEGY
        @no_pipeline_strategy = policy[:no_pipeline].presence || DEFAULT_NO_PIPELINE_STRATEGY
        @name = policy.fetch(:name)
        @actions = policy.fetch(:actions, []).map { |action| enrich_action(action) }
      end

      def skip_ci_allowed?(user_id)
        skip_ci_allowed_for_strategy?(skip_ci_strategy, user_id)
      end

      def no_pipeline_allowed?(user_id)
        no_pipeline_allowed_for_strategy?(no_pipeline_strategy, user_id)
      end

      private

      delegate :security_policy_management_project_id, :configuration_sha, to: :configuration, allow_nil: true

      def enrich_action(action)
        action.merge(metadata: build_metadata(action))
      end

      # Metadata used for id_tokens. It matches the attributes in `pipeline_execution_context.job_options`.
      def build_metadata(action)
        {
          name: name,
          project_id: security_policy_management_project_id,
          sha: configuration_sha,
          variables_override: variables_override_for(action)
        }.compact
      end

      def variables_override_for(action)
        explicit_keys = action[:variables]&.keys&.map(&:to_s) || []
        exceptions = (restricted_keys_for(action) + explicit_keys).uniq.presence

        { allowed: true }.tap do |options|
          options[:exceptions] = exceptions if exceptions
        end
      end

      def restricted_keys_for(action)
        SCAN_VARIABLES_WITH_RESTRICTED_VARIABLES.fetch(action[:scan]&.to_sym, {}).keys
      end
    end
  end
end
