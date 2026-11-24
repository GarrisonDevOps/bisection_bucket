# frozen_string_literal: true

module Vulnerabilities
  module Removal
    module Tasks
      # This task can potentially leave orphaned `vulnerability_remediations`
      # records behind if a record is not attached to any finding after deleting
      # the records from the join table.
      # This will be handled by https://gitlab.com/gitlab-org/gitlab/-/issues/486969
      class DeleteFindingRemediations < AbstractTaskScopedToFinding
        self.model = Vulnerabilities::FindingRemediation
      end
    end
  end
end
