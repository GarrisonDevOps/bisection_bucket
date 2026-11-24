# frozen_string_literal: true

module Types
  module MergeRequests
    module RiskAssessment
      class ConfidenceTierEnum < BaseEnum
        graphql_name 'MergeRequestRiskConfidenceTier'

        declarative_enum ::MergeRequests::RiskConfidenceTier
      end
    end
  end
end
