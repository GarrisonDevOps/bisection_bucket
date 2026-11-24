# frozen_string_literal: true

module Types
  module MergeRequests
    # rubocop:disable Graphql/AuthorizeTypes -- authorized through the merge request that owns the assessment
    class RiskAssessmentType < BaseObject
      graphql_name 'MergeRequestRiskAssessment'
      description 'Risk assessment for a merge request.'

      authorize_granular_token skip_reason: :parent_authorizes

      def self.authorization_scopes
        super + [:ai_workflows]
      end

      field :status, ::Types::MergeRequests::RiskAssessment::StatusEnum,
        null: false,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Status of the assessment.'

      field :risk, GraphQL::Types::Int,
        null: true,
        scopes: [:api, :read_api, :ai_workflows],
        method: :score,
        description: 'Risk score from 0 to 100.'

      field :confidence, GraphQL::Types::Int,
        null: true,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Confidence in the score, from 0 to 100. Derived from how much of the ' \
          'change could be measured and whether the signals agreed.'

      field :risk_tier, ::Types::MergeRequests::RiskAssessment::TierEnum,
        null: true,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Tier derived from the risk score.'

      field :confidence_tier, ::Types::MergeRequests::RiskAssessment::ConfidenceTierEnum,
        null: true,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Tier derived from the confidence score.'

      field :contributing_signals, [::Types::MergeRequests::RiskAssessment::ContributingSignalType],
        null: false,
        method: :signal_breakdown,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'What each signal contributed to the score.'

      field :contributions, [::Types::MergeRequests::RiskAssessment::ContributionType],
        null: false,
        method: :signal_breakdown,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'What each signal and risk domain contributed to the score.'

      field :missing_signals, [::Types::MergeRequests::RiskAssessment::MissingSignalType],
        null: false,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Signals that could not be measured, which is why confidence may be low.'

      field :domain_tags, [GraphQL::Types::String],
        null: false,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Risk domains the change touches, used to route specialist review.'

      field :rationale, GraphQL::Types::String,
        null: true,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Plain-language explanation of the assessment.'

      field :assessed_at, ::Types::TimeType,
        null: true,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'When the assessment completed.'

      field :stale, GraphQL::Types::Boolean,
        null: false,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Whether the merge request has changed since it was assessed. ' \
          'Assessment runs once, so this is a notice rather than a trigger to re-run.'

      field :duo_workflow_id, GraphQL::Types::Int,
        null: true,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'ID of the Duo workflow session that produced the assessment.'

      def stale
        object.diff_sha != object.merge_request.diff_head_sha
      end

      def risk_tier
        object.risk_tier&.to_s
      end

      def confidence_tier
        object.confidence_tier&.to_s
      end

      def status
        object.status_name.to_s
      end

      def missing_signals
        object.missing_signals.map { |key| { 'signal' => key } }
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
