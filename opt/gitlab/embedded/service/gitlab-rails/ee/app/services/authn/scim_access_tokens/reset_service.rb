# frozen_string_literal: true

module Authn
  module ScimAccessTokens
    class ResetService < BaseService
      VALID_SOURCES = %i[api_admin_token].freeze

      def initialize(current_user: nil, token: nil, audit_source: nil)
        @current_user = current_user
        @token = token
        @audit_source = audit_source

        raise ArgumentError unless VALID_SOURCES.include?(@audit_source)
      end

      def execute
        token.reset_token!
        log_event

        ServiceResponse.success
      end

      private

      attr_reader :token, :audit_source

      def log_event
        Gitlab::AppLogger.info(
          Labkit::Fields::CLASS_NAME => self.class.name,
          message: "SCIM token rotated",
          source: audit_source,
          reset_by: current_user&.username,
          token_id: token.id
        )
      end
    end
  end
end
