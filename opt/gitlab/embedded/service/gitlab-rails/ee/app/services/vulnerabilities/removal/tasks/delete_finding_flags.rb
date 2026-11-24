# frozen_string_literal: true

module Vulnerabilities
  module Removal
    module Tasks
      class DeleteFindingFlags < AbstractTaskScopedToFinding
        self.model = Vulnerabilities::Flag
      end
    end
  end
end
