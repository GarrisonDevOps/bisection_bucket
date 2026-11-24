# frozen_string_literal: true

module EE
  module Ci
    module PipelinePolicy
      extend ActiveSupport::Concern

      prepended do
        include TroubleshootJobPolicyHelper

        condition(:project_allows_read_dependency) do
          can?(:read_dependency, @subject.project)
        end

        rule do
          # `troubleshoot_job_with_ai` with a pipeline as a subject should be sufficient to show
          # the troubleshoot button.
          # We should ensure we check the ability `troubleshoot_job_with_ai` with a build as a subject
          # before sending job logs to and llm. i.e. user.can?(:troubleshoot_job_with_ai, job)
          can?(:read_build) &
            troubleshoot_job_licensed &
            troubleshoot_job_cloud_connector_authorized &
            troubleshoot_job_with_ai_authorized
        end.enable(:troubleshoot_job_with_ai)

        rule { project.admin_custom_role_enables_read_admin_cicd }.policy do
          enable :read_pipeline_metadata
        end

        rule { project_allows_read_dependency }.policy do
          enable :read_dependency
        end
      end
    end
  end
end
