# frozen_string_literal: true

module Govern
  module PolicyEngine
    module Impact
      # Outcome of one impact run. An unavailable result carries only the reason:
      # the rules or the scope need the engine, which the host-side run cannot ask.
      class Result < Data.define(:projects_in_scope_count, :violating_count, :violating_projects, :complete,
        :unavailable_reason)
        def self.unavailable(reason)
          new(projects_in_scope_count: 0, violating_count: 0, violating_projects: [], complete: false,
            unavailable_reason: reason)
        end

        def compliant_count
          projects_in_scope_count - violating_count
        end
      end
    end
  end
end
