# frozen_string_literal: true

module Types
  module MergeRequests
    class ApprovalRuleBlockageReasonEnum < BaseEnum
      graphql_name 'ApprovalRuleBlockageReasonKind'
      description 'Kind of reason why an approval rule blocks a merge request.'

      value 'BELOW_THRESHOLD', value: :below_threshold,
        description: 'Coverage is below the minimum coverage threshold of the rule.'
      value 'DECREASED', value: :decreased,
        description: 'Coverage decreased compared to the base pipeline.'
      value 'MISSING_BASE_COVERAGE', value: :missing_base_coverage,
        description: 'Base pipeline has no coverage to compare against.'
    end
  end
end
