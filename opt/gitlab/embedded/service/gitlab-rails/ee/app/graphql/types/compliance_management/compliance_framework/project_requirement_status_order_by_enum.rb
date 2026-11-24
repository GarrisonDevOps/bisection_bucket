# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      class ProjectRequirementStatusOrderByEnum < BaseEnum
        graphql_name 'ProjectComplianceRequirementStatusOrderBy'
        description 'Values for order_by field for project requirement statuses.'

        value 'PROJECT', 'Order by projects.', value: 'project'
        value 'REQUIREMENT', 'Order by requirements.', value: 'requirement'
        value 'FRAMEWORK', 'Order by frameworks.', value: 'framework'
      end
    end
  end
end
