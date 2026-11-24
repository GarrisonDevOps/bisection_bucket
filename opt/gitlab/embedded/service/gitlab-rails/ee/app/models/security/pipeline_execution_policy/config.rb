# frozen_string_literal: true

# This class is the object representation of a single entry in the policy.yml
module Security
  module PipelineExecutionPolicy
    class Config
      include Gitlab::Utils::StrongMemoize
      include ::Security::PolicyCiSkippable
      include ::Security::PolicyNoPipeline

      DEFAULT_SUFFIX_STRATEGY = 'on_conflict'
      DEFAULT_CONFIG_STRATEGY = :inject_policy
      SUFFIX_STRATEGIES = { on_conflict: 'on_conflict', never: 'never' }.freeze
      DEFAULT_SKIP_CI_STRATEGY = { allowed: false }.freeze
      DEFAULT_APPLY_ON_EMPTY_PIPELINE = 'always'
      DEFAULT_NO_PIPELINE_STRATEGY = { allowed: false }.freeze
      POLICY_JOB_SUFFIX = ':policy'

      attr_reader :content, :config_strategy, :suffix_strategy, :policy_project_id, :policy_index, :name,
        :skip_ci_strategy, :no_pipeline_strategy, :policy_config, :policy_sha, :apply_on_empty_pipeline,
        :variables_override_strategy

      delegate :experiment_enabled?, to: :policy_config

      def initialize(policy:, policy_config:, policy_index:)
        @content = policy[:content]&.to_yaml
        @policy_config = policy_config
        @policy_project_id = policy_config.security_policy_management_project_id
        @policy_index = policy_index
        parse_pipeline_config_strategy(policy[:pipeline_config_strategy])
        @suffix_strategy = policy[:suffix] || DEFAULT_SUFFIX_STRATEGY
        @name = policy.fetch(:name)
        @skip_ci_strategy = policy[:skip_ci].presence || DEFAULT_SKIP_CI_STRATEGY
        @no_pipeline_strategy = policy[:no_pipeline].presence || DEFAULT_NO_PIPELINE_STRATEGY
        @variables_override_strategy = policy[:variables_override]&.deep_symbolize_keys
        @enforce_on_child_pipelines = policy[:enforce_on_child_pipelines] == true
        # Don't delegate to policy_config to ensure it doesn't change while building the pipeline
        @policy_sha = policy_config.configuration_sha
      end

      def strategy_override_project_ci?
        config_strategy == :override_project_ci
      end

      # New inject CI strategy that allows custom policy stages to be injected into the project CI config.
      # It is going to replace `inject_ci` strategy.
      def strategy_inject_policy?
        config_strategy == :inject_policy
      end

      def suffix
        return if suffix_strategy == SUFFIX_STRATEGIES[:never]

        [POLICY_JOB_SUFFIX, policy_project_id, policy_index].join("-")
      end
      strong_memoize_attr :suffix

      def suffix_on_conflict?
        suffix_strategy == SUFFIX_STRATEGIES[:on_conflict]
      end

      def skip_ci_allowed?(user_id)
        skip_ci_allowed_for_strategy?(skip_ci_strategy, user_id)
      end

      def no_pipeline_allowed?(user_id)
        no_pipeline_allowed_for_strategy?(no_pipeline_strategy, user_id)
      end

      # The experiment fallback keeps existing configurations working and will be removed in
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/632456.
      def enforce_on_child_pipelines?
        @enforce_on_child_pipelines || experiment_enabled?(:enforce_pipeline_policy_on_child_pipelines)
      end

      private

      def parse_pipeline_config_strategy(strategy_config)
        if strategy_config.is_a?(Hash)
          @config_strategy = strategy_config.fetch(:type, DEFAULT_CONFIG_STRATEGY).to_sym
          @apply_on_empty_pipeline = strategy_config.fetch(
            :apply_on_empty_pipeline, DEFAULT_APPLY_ON_EMPTY_PIPELINE
          ).to_s
        else
          @config_strategy = strategy_config&.to_sym || DEFAULT_CONFIG_STRATEGY
          @apply_on_empty_pipeline = DEFAULT_APPLY_ON_EMPTY_PIPELINE
        end
      end
    end
  end
end
