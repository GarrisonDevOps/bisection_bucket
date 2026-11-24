# frozen_string_literal: true

# Worker for creating and updating token status records for findings from security scans.
#
# This worker processes secret detection findings from a pipeline and creates
# or updates FindingTokenStatus records that indicate whether detected tokens
# match known personal access tokens and their current status.
#
module Security
  module SecretDetection
    class GitlabTokenVerificationWorker
      include ApplicationWorker

      feature_category :secret_detection
      data_consistency :sticky

      idempotent!

      concurrency_limit -> { 20 }

      # Creates or updates FindingTokenStatus records for secret detection findings in a pipeline.
      #
      # @param [Integer] pipeline_id ID of the pipeline containing security scan results
      def perform(pipeline_id)
        pipeline = Ci::Pipeline.find_by_id(pipeline_id)
        return unless pipeline

        service = ::Security::SecretDetection::UpdateTokenStatusService.new

        if pipeline.default_branch?
          service.execute_for_vulnerability_pipeline(pipeline_id)
        else
          service.execute_for_security_pipeline(pipeline_id)
        end
      end
    end
  end
end
