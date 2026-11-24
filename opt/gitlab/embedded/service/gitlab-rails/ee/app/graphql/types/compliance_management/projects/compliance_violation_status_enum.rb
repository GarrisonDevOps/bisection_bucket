# frozen_string_literal: true

module Types
  module ComplianceManagement
    module Projects
      class ComplianceViolationStatusEnum < BaseEnum
        graphql_name 'ComplianceViolationStatus'
        description 'Compliance violation status of the project.'

        ::Enums::ComplianceManagement::Projects::ComplianceViolation.status.each_key do |status|
          value status.to_s.upcase, value: status.to_s, description: status.to_s.humanize
        end
      end
    end
  end
end
