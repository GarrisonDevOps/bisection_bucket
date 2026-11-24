# frozen_string_literal: true

module Types
  module MergeRequests
    module RiskAssessment
      # rubocop:disable Graphql/AuthorizeTypes -- authorized through the merge request that owns the assessment
      class MissingSignalType < BaseObject
        graphql_name 'MergeRequestRiskMissingSignal'
        description 'A signal that could not be measured for a merge request risk assessment.'

        include SignalLabelFields

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
