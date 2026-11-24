# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ProjectControlStatuses
      class BulkDestroyService
        BATCH_SIZE = 100

        def initialize(project_id, framework_id)
          @project_id = project_id
          @framework_id = framework_id
        end

        def execute
          requirements = ComplianceManagement::ComplianceFramework::ComplianceRequirement.for_framework(framework_id)

          ProjectControlComplianceStatus
            .for_projects([project_id])
            .for_requirements(requirements)
            .delete_all

          ServiceResponse.success(message: _('Successfully deleted requirement statuses'))
        end

        private

        attr_reader :project_id, :framework_id
      end
    end
  end
end
