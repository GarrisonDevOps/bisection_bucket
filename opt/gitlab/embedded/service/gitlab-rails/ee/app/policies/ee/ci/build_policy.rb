# frozen_string_literal: true

module EE
  module Ci
    module BuildPolicy
      extend ActiveSupport::Concern

      prepended do
        include TroubleshootJobPolicyHelper

        rule do
          can?(:read_build_trace) &
            troubleshoot_job_licensed &
            troubleshoot_job_cloud_connector_authorized &
            troubleshoot_job_with_ai_authorized
        end.enable(:troubleshoot_job_with_ai)

        rule { project.admin_custom_role_enables_read_admin_cicd }.policy do
          enable :read_build_metadata
        end
      end
    end
  end
end
