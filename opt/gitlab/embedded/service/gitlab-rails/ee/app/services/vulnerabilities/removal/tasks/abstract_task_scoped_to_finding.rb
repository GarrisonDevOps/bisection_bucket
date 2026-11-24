# frozen_string_literal: true

module Vulnerabilities
  module Removal
    module Tasks
      class AbstractTaskScopedToFinding < AbstractTask
        private

        def relation
          model.by_finding_id(parent_ids).limit(100)
        end
      end
    end
  end
end
