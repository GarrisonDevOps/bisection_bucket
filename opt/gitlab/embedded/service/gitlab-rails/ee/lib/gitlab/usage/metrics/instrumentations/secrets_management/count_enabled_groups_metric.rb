# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        module SecretsManagement
          class CountEnabledGroupsMetric < DatabaseMetric
            relation do
              ::SecretsManagement::GroupSecretsManager
              .where(status: ::SecretsManagement::GroupSecretsManager::STATUSES[:active])
            end

            operation :count
          end
        end
      end
    end
  end
end
