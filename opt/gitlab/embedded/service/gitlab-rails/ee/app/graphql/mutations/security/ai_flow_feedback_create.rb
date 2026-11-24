# frozen_string_literal: true

module Mutations
  module Security
    class AiFlowFeedbackCreate < BaseMutation
      graphql_name 'SecurityAiFlowFeedbackCreate'
      description 'Submits feedback on the latest AI assessment of a vulnerability, such as a false positive ' \
        'detection. Emits an internal event and stores nothing.'

      NOT_AVAILABLE_REASONS = %i[feature_disabled].freeze
      MAX_REASONS = 5

      authorize :create_security_ai_flow_feedback

      authorize_granular_token permissions: :create_security_ai_flow_feedback,
        boundary_argument: :vulnerability_id, boundary: :project, boundary_type: :project

      argument :vulnerability_id,
        ::Types::GlobalIDType[::Vulnerability],
        required: true,
        description: 'Global ID of the vulnerability whose latest AI assessment the feedback is about.'

      argument :sentiment,
        ::Types::Security::AiFlowFeedbackSentimentEnum,
        required: true,
        description: 'Sentiment of the feedback.'

      argument :reasons,
        [::Types::Security::AiFlowFeedbackReasonEnum],
        required: false,
        validates: { length: { maximum: MAX_REASONS } },
        description: 'Reasons for the feedback. Only allowed when the sentiment is `DISAGREE`. ' \
          "Maximum #{MAX_REASONS} reasons."

      def resolve(vulnerability_id:, sentiment:, reasons: nil)
        vulnerability = authorized_find!(id: vulnerability_id)

        result = ::Vulnerabilities::SecurityAiFlowFeedbacks::CreateService.new(
          current_user: current_user,
          vulnerability: vulnerability,
          sentiment: sentiment,
          reasons: reasons
        ).execute

        raise_resource_not_available_error! if NOT_AVAILABLE_REASONS.include?(result.reason)

        { errors: result.success? ? [] : [result.message] }
      end
    end
  end
end
