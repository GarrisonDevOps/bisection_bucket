# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountActiveServiceAccountsMetric < DatabaseMetric
          operation :distinct_count

          timestamp_column :updated_at

          relation do
            User.service_account.where(state: 'active')
          end
        end
      end
    end
  end
end
