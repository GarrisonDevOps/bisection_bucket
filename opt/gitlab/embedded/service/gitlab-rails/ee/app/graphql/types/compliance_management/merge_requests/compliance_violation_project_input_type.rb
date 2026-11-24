# frozen_string_literal: true

module Types
  module ComplianceManagement
    module MergeRequests
      class ComplianceViolationProjectInputType < BaseInputObject
        graphql_name 'ComplianceViolationProjectInput'

        argument :merged_before, ::Types::DateType,
          required: false,
          description: 'Merge requests merged before the date (inclusive).'

        argument :merged_after, ::Types::DateType,
          required: false,
          description: 'Merge requests merged after the date (inclusive).'

        argument :target_branch, ::GraphQL::Types::String,
          required: false,
          description: 'Filter compliance violations by target branch.'
      end
    end
  end
end
