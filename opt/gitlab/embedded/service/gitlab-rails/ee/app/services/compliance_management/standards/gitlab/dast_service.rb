# frozen_string_literal: true

module ComplianceManagement
  module Standards
    module Gitlab
      class DastService < BaseService
        CHECK_NAME = :dast

        private

        def status
          pipeline = project.latest_pipeline_for_ci_and_security_orchestration

          return :fail if pipeline.nil?

          pipeline.job_artifacts.dast.count > 0 ? :success : :fail
        end
      end
    end
  end
end
