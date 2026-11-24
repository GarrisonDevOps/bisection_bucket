# frozen_string_literal: true

module EE
  module Ci
    module Queue
      module PendingBuildsStrategy
        extend ActiveSupport::Concern

        def enforce_minutes_limit(relation)
          relation.with_ci_minutes_available
        end

        def enforce_allowed_plan_name_uids(relation, allowed_plan_name_uids)
          relation.with_allowed_plan_name_uids(allowed_plan_name_uids)
        end
      end
    end
  end
end
