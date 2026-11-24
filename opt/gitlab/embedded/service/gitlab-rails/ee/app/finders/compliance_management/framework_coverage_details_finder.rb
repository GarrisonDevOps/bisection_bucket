# frozen_string_literal: true

# FrameworkCoverageDetailsFinder
#
# Used to find compliance frameworks with project coverage details
#
# Arguments:
#   framework_ids: [integer] - IDs of frameworks to filter by
#   project_ids: [integer] - IDs of projects to calculate coverage for
module ComplianceManagement
  class FrameworkCoverageDetailsFinder
    attr_reader :framework_ids, :project_ids

    def initialize(framework_ids:, project_ids:)
      @framework_ids = framework_ids
      @project_ids = project_ids
    end

    def execute
      ComplianceManagement::Framework.for_coverage_details(
        framework_ids: framework_ids,
        project_ids: project_ids
      )
    end
  end
end
