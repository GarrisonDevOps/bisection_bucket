# frozen_string_literal: true

module EE
  module Ci
    module PipelinesHelper
      extend ::Gitlab::Utils::Override

      override :pipelines_list_data
      def pipelines_list_data(project)
        super.merge(
          identity_verification_required: show_iv_alert_for_pipelines_list?(project).to_s,
          identity_verification_path: identity_verification_path
        )
      end

      override :new_pipeline_data
      def new_pipeline_data(project)
        super.merge(
          identity_verification_path: identity_verification_path
        )
      end

      private

      def show_iv_alert_for_pipelines_list?(project)
        return false unless current_user

        !::Users::IdentityVerification::AuthorizeCi.new(user: current_user, project: project).user_can_run_jobs?
      end
    end
  end
end
