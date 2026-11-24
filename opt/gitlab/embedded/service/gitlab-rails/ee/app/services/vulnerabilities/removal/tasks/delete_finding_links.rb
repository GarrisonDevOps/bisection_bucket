# frozen_string_literal: true

module Vulnerabilities
  module Removal
    module Tasks
      class DeleteFindingLinks < AbstractTaskScopedToFinding
        self.model = Vulnerabilities::FindingLink
      end
    end
  end
end
