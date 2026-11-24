# frozen_string_literal: true

module Vulnerabilities
  module Removal
    module Tasks
      class DeleteFindingEvidences < AbstractTaskScopedToFinding
        self.model = Vulnerabilities::Finding::Evidence
      end
    end
  end
end
