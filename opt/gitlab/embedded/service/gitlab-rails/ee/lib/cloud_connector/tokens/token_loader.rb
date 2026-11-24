# frozen_string_literal: true

module CloudConnector
  module Tokens
    class TokenLoader
      # for SelfManaged/Dedicated instances we are using an instance token synced from CustomersDot
      def token
        # Lease a connection explicitly: this may be called from background threads
        # (e.g. the billing Snowplow emitter) that run outside a Rails executor.
        ::CloudConnector::ServiceAccessToken.with_connection do
          ::CloudConnector::ServiceAccessToken.active.last&.token
        end
      end
    end
  end
end
