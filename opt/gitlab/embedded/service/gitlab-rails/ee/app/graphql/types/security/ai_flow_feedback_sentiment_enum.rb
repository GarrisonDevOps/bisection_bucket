# frozen_string_literal: true

module Types
  module Security
    class AiFlowFeedbackSentimentEnum < BaseEnum
      graphql_name 'SecurityAiFlowFeedbackSentiment'
      description 'Sentiment of feedback on a security AI flow result.'

      DESCRIPTIONS = {
        'agree' => 'User agrees with the AI flow result.',
        'disagree' => 'User disagrees with the AI flow result.'
      }.freeze

      ::Vulnerabilities::SecurityAiFlowFeedbacks::CreateService::SENTIMENTS.each do |sentiment|
        value sentiment.upcase, description: DESCRIPTIONS.fetch(sentiment), value: sentiment
      end
    end
  end
end
