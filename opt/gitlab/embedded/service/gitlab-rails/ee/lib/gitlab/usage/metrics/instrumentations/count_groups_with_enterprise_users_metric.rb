# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountGroupsWithEnterpriseUsersMetric < DatabaseMetric
          operation :distinct_count, column: :enterprise_group_id

          relation do
            UserDetail.with_enterprise_group
          end
        end
      end
    end
  end
end
