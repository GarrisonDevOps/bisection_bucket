# frozen_string_literal: true

module Types
  module Vulnerabilities
    module FindingDueDates
      class FindingDueDatesSetInputType < BaseInputObject
        graphql_name 'FindingDueDatesSetInput'

        argument :finding_uuid,
          GraphQL::Types::String,
          required: true,
          description: 'UUID of the vulnerability finding.'

        argument :due_date,
          Types::DateType,
          required: false,
          description: 'Due date for the finding. Pass null to remove.'
      end
    end
  end
end
