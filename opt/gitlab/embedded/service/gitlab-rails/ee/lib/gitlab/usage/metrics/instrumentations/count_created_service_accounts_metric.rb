# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountCreatedServiceAccountsMetric < DatabaseMetric
          operation :distinct_count

          timestamp_column :created_at

          relation do
            User.service_account
          end
        end
      end
    end
  end
end
