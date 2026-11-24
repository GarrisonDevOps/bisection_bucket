# frozen_string_literal: true

module Vulnerabilities
  module Removal
    module Tasks
      class DeleteFindingSignatures < AbstractTaskScopedToFinding
        self.model = Vulnerabilities::FindingSignature
      end
    end
  end
end
