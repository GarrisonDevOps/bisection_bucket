# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountSlackDuoScopedInstallationsMetric < DatabaseMetric
          operation :distinct_count, column: 'slack_integrations_scopes.slack_integration_id'

          relation do
            ::Integrations::SlackWorkspace::IntegrationApiScope
              .joins(:slack_api_scope)
              .where(slack_api_scopes: { name: ::SlackIntegration::SCOPE_APP_MENTIONS_READ })
          end
        end
      end
    end
  end
end
