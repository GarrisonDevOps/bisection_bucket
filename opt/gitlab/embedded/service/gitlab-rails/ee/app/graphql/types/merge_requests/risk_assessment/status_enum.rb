# frozen_string_literal: true

module Types
  module MergeRequests
    module RiskAssessment
      class StatusEnum < BaseEnum
        graphql_name 'MergeRequestRiskAssessmentStatus'

        declarative_enum ::MergeRequests::RiskAssessmentStatus
      end
    end
  end
end
