# frozen_string_literal: true

module Types
  module MergeRequests
    module RiskAssessment
      # rubocop:disable Graphql/AuthorizeTypes -- authorized through the merge request that owns the assessment
      class ContributingSignalType < BaseObject
        graphql_name 'MergeRequestRiskContributingSignal'
        description 'Contribution a single signal made to a merge request risk score.'

        include SignalLabelFields

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :contribution, GraphQL::Types::Float,
          null: false,
          hash_key: 'contribution',
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Points the signal added to the overall score.'

        field :detail, GraphQL::Types::String,
          null: true,
          hash_key: 'detail',
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Human-readable explanation of the contribution.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
