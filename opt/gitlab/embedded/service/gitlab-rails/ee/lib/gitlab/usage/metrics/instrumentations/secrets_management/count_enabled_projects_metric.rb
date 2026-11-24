# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        module SecretsManagement
          class CountEnabledProjectsMetric < DatabaseMetric
            relation do
              ::SecretsManagement::ProjectSecretsManager
              .where(status: ::SecretsManagement::ProjectSecretsManager::STATUSES[:active])
            end

            operation :count
          end
        end
      end
    end
  end
end
