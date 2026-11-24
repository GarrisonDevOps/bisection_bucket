# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountUsersWithMinimalAccessMetric < DatabaseMetric
          operation :count

          start { User.active.minimum(:id) }
          finish { User.active.maximum(:id) }

          relation do
            User.active.joins(:user_highest_role).where(
              user_highest_roles: { highest_access_level: Gitlab::Access::MINIMAL_ACCESS }
            )
          end
        end
      end
    end
  end
end
