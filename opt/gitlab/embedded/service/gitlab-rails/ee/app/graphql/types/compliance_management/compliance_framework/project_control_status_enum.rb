# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      class ProjectControlStatusEnum < BaseEnum
        graphql_name 'ProjectComplianceControlStatus'
        description 'Compliance status of the project control.'

        ::Enums::ComplianceManagement::ComplianceFramework::ProjectControlComplianceStatus.status.each_key do |status|
          value status.to_s.upcase, value: status.to_s, description: status.to_s.humanize
        end
      end
    end
  end
end
