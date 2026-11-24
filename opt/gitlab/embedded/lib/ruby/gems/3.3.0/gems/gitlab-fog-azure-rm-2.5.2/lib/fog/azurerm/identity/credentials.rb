module Fog
  module AzureRM
    module Identity
      # Credentials stores the access token and its expiry.
      class Credentials
        attr_accessor :token, :expires_at

        EXPIRATION_BUFFER = 600 # 10 minutes

        def initialize(token, expires_at)
          @token = token
          @expires_at = expires_at
        end

        def refresh_needed?
          return true unless expires_at

          Time.now >= expires_at - EXPIRATION_BUFFER
        end
      end
    end
  end
end
