# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class PipelineFailedAuditor < PipelineAuditor
      private

      def event_name
        'security_policy_pipeline_failed'
      end

      def event_message
        "Pipeline: #{pipeline.id} created by security policies or with security policy jobs failed"
      end
    end
  end
end
