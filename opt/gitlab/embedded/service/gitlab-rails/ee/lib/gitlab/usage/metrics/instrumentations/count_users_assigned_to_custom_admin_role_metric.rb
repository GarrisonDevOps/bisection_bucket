# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountUsersAssignedToCustomAdminRoleMetric < DatabaseMetric
          operation :distinct_count, column: :user_id

          relation do
            Users::UserMemberRole
          end
        end
      end
    end
  end
end
