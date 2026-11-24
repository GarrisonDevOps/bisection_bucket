# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class VerificationStatusInputType < BaseInputObject
        graphql_name 'VerificationStatusInput'

        argument :verification_status, ::Types::RequirementsManagement::TestReportStateEnum,
          required: true,
          description: 'Verification status of the work item.'
      end
    end
  end
end
