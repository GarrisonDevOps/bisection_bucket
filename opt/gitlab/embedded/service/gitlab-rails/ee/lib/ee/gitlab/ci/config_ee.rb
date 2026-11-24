# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      # This is named ConfigEE to avoid collisions with the
      # EE::Gitlab::Ci::Config namespace
      module ConfigEE
        extend ::Gitlab::Utils::Override

        override :initialize
        def initialize(config, scan_profile_context: nil, **args)
          @scan_profile_context = scan_profile_context
          super(config, **args)
        end

        private

        attr_reader :scan_profile_context

        override :rescue_errors
        def rescue_errors
          [
            *super,
            ::Gitlab::Ci::Config::Required::Processor::RequiredError
          ]
        end

        override :build_config
        def build_config(config, inputs)
          super
            .then { |config| process_required_includes(config) }
            .then { |config| enforce_pipeline_execution_policy_stages(config) }
            .then { |config| process_security_orchestration_policy_includes(config) }
            .then { |config| process_security_scan_profiles_includes(config) }
        end

        def process_required_includes(config)
          return config unless required_pipelines_enabled?

          ::Gitlab::Ci::Config::Required::Processor.new(config).perform
        end

        def enforce_pipeline_execution_policy_stages(config)
          policy_context = pipeline_policy_context&.pipeline_execution_context
          return config if policy_context.nil?

          logger.instrument(:config_pipeline_execution_policy_stages_inject, once: true) do
            policy_context.enforce_stages!(config: config)
          end
        rescue ::Gitlab::Ci::Config::StagesMerger::InvalidStageConditionError => e
          raise ::Gitlab::Ci::Config::ConfigError, e.message
        end

        def process_security_orchestration_policy_includes(config)
          return config if skip_policy_scan_injection?

          logger.instrument(:config_scan_execution_policy_processor, once: true) do
            ::Gitlab::Ci::Config::SecurityOrchestrationPolicies::Processor.new(config, context, source_ref_path,
              pipeline_policy_context).perform
          end
        end

        def process_security_scan_profiles_includes(config)
          return config if skip_policy_scan_injection?

          ::Gitlab::Ci::Config::SecurityScanProfiles::Processor.new(config, context, source_ref_path, source).perform
        end

        # We need to prevent policy scans (SEP jobs and security scan profile
        # jobs) from being injected into PEP pipelines because they need to be
        # added only into the main pipeline. This applies both to policy
        # pipelines built during PEP creation and to scheduled PEP pipelines.
        def skip_policy_scan_injection?
          policy_context = pipeline_policy_context&.pipeline_execution_context
          return false if policy_context.nil?

          policy_context.creating_any_policy_pipeline?
        end

        def required_pipelines_enabled?
          @project.present? && ::Feature.enabled?(:required_pipelines, @project) # rubocop:disable Gitlab/ModuleWithInstanceVariables -- temporary usage
        end

        override :build_context
        def build_context(**args)
          super.tap do |context|
            context.scan_profile_context = scan_profile_context
          end
        end
      end
    end
  end
end
