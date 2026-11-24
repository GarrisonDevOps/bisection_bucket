# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      module SelfHosted
        class BillingDuoWorkflowServiceProbe < DuoAgentPlatformProbe
          extend ::Gitlab::Utils::Override

          def initialize(user)
            super(user, deployment: :cloud_connected)
          end

          private

          override :success_message
          def success_message
            format(
              s_('HealthCheck|The cloud GitLab Duo Agent Platform service at %{host} is reachable ' \
                'for usage billing.'),
              host: host
            )
          end

          override :failure_message
          def failure_message
            format(
              s_('HealthCheck|The cloud GitLab Duo Agent Platform service at %{host} is not reachable. ' \
                'Self-hosted GitLab Duo usage billing will fail until connectivity is restored.'),
              host: host
            )
          end
        end
      end
    end
  end
end
