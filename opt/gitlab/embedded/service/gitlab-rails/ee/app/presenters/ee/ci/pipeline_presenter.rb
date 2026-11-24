# frozen_string_literal: true

module EE
  module Ci
    module PipelinePresenter
      extend ActiveSupport::Concern

      def expose_security_dashboard?
        return false unless can?(current_user, :read_security_resource, pipeline.project)

        latest_report_builds_in_self_and_project_descendants(
          ::Ci::JobArtifact.with_file_types(security_report_file_types)
        ).exists?
      end

      def security_report_file_types
        ::Enums::Ci::JobArtifact.security_report_and_cyclonedx_report_file_types
      end

      def degradation_threshold(file_type)
        if (job_artifact = batch_lookup_report_artifact_for_file_type(file_type)) &&
            can?(current_user, :read_build, job_artifact.job)
          job_artifact.job.degradation_threshold
        end
      end
    end
  end
end
