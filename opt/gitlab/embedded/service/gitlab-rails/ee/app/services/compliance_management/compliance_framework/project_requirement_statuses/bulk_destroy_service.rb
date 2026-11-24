# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ProjectRequirementStatuses
      class BulkDestroyService
        BATCH_SIZE = 100

        def initialize(project_id, framework_id)
          @project_id = project_id
          @framework_id = framework_id
        end

        def execute
          ComplianceManagement::ComplianceFramework::ProjectRequirementComplianceStatus.for_projects([project_id])
            .for_frameworks([framework_id]).each_batch(of: BATCH_SIZE) do |batch|
            batch.delete_all
          end

          ServiceResponse.success(message: _('Successfully deleted requirement statuses.'))
        end

        private

        attr_reader :project_id, :framework_id
      end
    end
  end
end
