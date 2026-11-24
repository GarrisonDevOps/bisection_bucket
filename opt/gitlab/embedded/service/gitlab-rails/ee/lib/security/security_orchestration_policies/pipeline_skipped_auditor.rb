# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class PipelineSkippedAuditor < PipelineAuditor
      private

      def event_name
        'security_policy_pipeline_skipped'
      end

      def event_message
        "Pipeline: #{pipeline.id} with security policy jobs skipped"
      end
    end
  end
end
