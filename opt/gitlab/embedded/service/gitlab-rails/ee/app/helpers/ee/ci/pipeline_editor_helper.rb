# frozen_string_literal: true

module EE
  module Ci
    module PipelineEditorHelper
      extend ::Gitlab::Utils::Override

      override :js_pipeline_editor_data
      def js_pipeline_editor_data(project)
        result = super

        if project.licensed_feature_available?(:api_fuzzing)
          result.merge!(
            "api-fuzzing-configuration-path" => project_security_configuration_api_fuzzing_path(project),
            "dast-configuration-path" => project_security_configuration_dast_path(project)
          )
        end

        result["resource-id"] = project.to_global_id.to_s
        result["identity-verification-required"] = identity_verification_required_for_pipeline?(project).to_s
        result["identity-verification-path"] = identity_verification_path

        result
      end

      private

      def identity_verification_required_for_pipeline?(project)
        return false unless current_user

        !::Users::IdentityVerification::AuthorizeCi.new(user: current_user, project: project).user_can_run_jobs?
      end
    end
  end
end
