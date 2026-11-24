# frozen_string_literal: true

module Types
  module Security
    class AiFlowFeedbackReasonEnum < BaseEnum
      graphql_name 'SecurityAiFlowFeedbackReason'
      description 'Reasons for disagreeing with a security AI flow result.'

      DESCRIPTIONS = {
        'verdict_wrong' => 'Verdict of the AI flow is wrong.',
        'ignored_data_flow' => 'AI flow ignored the data flow of the finding.',
        'explanation_inaccurate' => 'Explanation of the AI flow is inaccurate.',
        'confidence_miscalibrated' => 'Confidence score of the AI flow does not match the result.',
        'other' => 'Other reason.'
      }.freeze

      ::Vulnerabilities::SecurityAiFlowFeedbacks::CreateService::REASONS.each do |reason|
        value reason.upcase, description: DESCRIPTIONS.fetch(reason), value: reason
      end
    end
  end
end
