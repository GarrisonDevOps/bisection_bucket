# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Components
        module InstancePath
          extend ::Gitlab::Utils::Override

          private

          override :access_allowed?
          def access_allowed?(current_user)
            super || pipeline_execution_policy_component_access_allowed?
          end

          def pipeline_execution_policy_component_access_allowed?
            execution_context = pipeline_policy_context&.pipeline_execution_context
            return false unless execution_context

            instrument(:config_component_validate_policy_access) do
              template_file_paths.any? do |file_path|
                execution_context.ci_config_access_allowed?(config_project: project, file_path: file_path)
              end
            end
          end
        end
      end
    end
  end
end
