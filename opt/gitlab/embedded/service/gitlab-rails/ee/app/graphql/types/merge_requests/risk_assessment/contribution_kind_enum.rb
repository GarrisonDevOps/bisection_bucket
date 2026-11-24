# frozen_string_literal: true

module Types
  module MergeRequests
    module RiskAssessment
      class ContributionKindEnum < BaseEnum
        graphql_name 'MergeRequestRiskContributionKind'
        description 'What made a contribution to a merge request risk score.'

        value 'SIGNAL', value: 'signal', description: 'Signal measured from the merge request.'
        value 'DOMAIN', value: 'domain', description: 'Risk domain the classification flagged as touched.'
      end
    end
  end
end
