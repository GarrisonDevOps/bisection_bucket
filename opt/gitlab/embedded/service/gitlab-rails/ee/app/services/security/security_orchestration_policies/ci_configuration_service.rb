# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class CiConfigurationService < ::BaseProjectService
      ACTION_CLASSES = {
        'secret_detection' => CiAction::Template,
        'container_scanning' => CiAction::Template,
        'sast' => CiAction::Template,
        'sast_iac' => CiAction::Template,
        'dependency_scanning' => CiAction::Template
      }.freeze

      def execute(action, ci_variables, context, index = 0)
        action_class = ACTION_CLASSES[action[:scan]] || CiAction::Unknown

        opts = {
          template_cache: params[:template_cache],
          job_name_suffix: params[:job_name_suffix],
          inputs: params[:inputs]
        }

        action_class.new(action, ci_variables, context, index, opts).config
      end
    end
  end
end
