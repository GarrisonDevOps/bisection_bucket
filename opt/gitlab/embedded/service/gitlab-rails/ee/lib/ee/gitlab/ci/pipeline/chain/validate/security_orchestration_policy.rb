# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module Validate
            module SecurityOrchestrationPolicy
              extend ::Gitlab::Utils::Override
              include ::Gitlab::Ci::Pipeline::Chain::Helpers

              override :perform!
              def perform!
                # Skip this step in context of pipeline execution policies
                return if command.pipeline_policy_context.pipeline_execution_context.creating_policy_pipeline?
                return unless project&.feature_available?(:security_orchestration_policies)
                return unless security_orchestration_policy_configuration

                if !security_orchestration_policy_configuration.policy_configuration_exists?
                  warning(format(_('scan-execution-policy: policy not applied, %{policy_path} file is missing'), policy_path: ::Security::OrchestrationPolicyConfiguration::POLICY_PATH))
                elsif !security_orchestration_policy_configuration.policy_configuration_valid?
                  warning(format(_('scan-execution-policy: policy not applied, %{policy_path} file is invalid'), policy_path: ::Security::OrchestrationPolicyConfiguration::POLICY_PATH))
                end
              end

              delegate :security_orchestration_policy_configuration, to: :project, allow_nil: true
            end
          end
        end
      end
    end
  end
end
