# frozen_string_literal: true

module Types
  module MergeRequests
    module RiskAssessment
      class TierEnum < BaseEnum
        graphql_name 'MergeRequestRiskTier'

        declarative_enum ::MergeRequests::RiskTier
      end
    end
  end
end
