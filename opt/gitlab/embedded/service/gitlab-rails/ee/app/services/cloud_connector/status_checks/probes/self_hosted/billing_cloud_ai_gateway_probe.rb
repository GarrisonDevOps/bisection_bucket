# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      module SelfHosted
        class BillingCloudAiGatewayProbe < HostProbe
          def initialize
            super(::Gitlab::AiGateway.cloud_connector_url)
          end
        end
      end
    end
  end
end
