# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      module SelfHosted
        class BillingCustomersDotProbe < HostProbe
          def initialize
            super(::Gitlab::Routing.url_helpers.subscription_portal_url)
          end
        end
      end
    end
  end
end
