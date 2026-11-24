# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class VerificationStatusFilterInputType < BaseInputObject
        graphql_name 'VerificationStatusFilterInput'

        argument :verification_status, ::Types::RequirementsManagement::RequirementStatusFilterEnum,
          required: true,
          description: 'Verification status of the work item.'
      end
    end
  end
end
