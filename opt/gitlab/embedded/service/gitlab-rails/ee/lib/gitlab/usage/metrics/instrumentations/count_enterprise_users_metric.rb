# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountEnterpriseUsersMetric < DatabaseMetric
          operation :count

          relation do
            UserDetail.with_enterprise_group
          end
        end
      end
    end
  end
end
