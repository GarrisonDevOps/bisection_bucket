# frozen_string_literal: true

module Vulnerabilities
  module Removal
    module Tasks
      class DeleteFindingIdentifiers < AbstractTaskScopedToFinding
        self.model = Vulnerabilities::FindingIdentifier
      end
    end
  end
end
