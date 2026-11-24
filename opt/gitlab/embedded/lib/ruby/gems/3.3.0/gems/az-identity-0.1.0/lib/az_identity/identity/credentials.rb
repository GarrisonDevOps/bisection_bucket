# frozen_string_literal: true

module AzIdentity
  module Identity
    class Credentials
      attr_accessor :token, :expires_at

      EXPIRATION_BUFFER = 600

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
