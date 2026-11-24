# frozen_string_literal: true

# Implements a parser for the "Exposed-Credential-Check" header
# set by CloudFlare's "Leaked credential detection" feature and
# managed request header transform.
#
# Documentation for possible values:
# https://developers.cloudflare.com/rules/transform/managed-transforms/reference/#add-leaked-credentials-checks-header
module Gitlab
  module Auth
    class CloudflareExposedCredentialChecker
      HEADER_VALUES = {
        "1" => :exact_username_and_password,
        "2" => :exact_username,
        "3" => :similar_username_and_password,
        "4" => :exact_password
      }.freeze

      attr_reader :request, :result

      def initialize(request)
        @request = request
        @result = HEADER_VALUES[request.headers['HTTP_EXPOSED_CREDENTIAL_CHECK']]
      end

      def exact_username_and_password?
        exact_username? && exact_password?
      end

      def exact_username?
        [:exact_username, :exact_username_and_password].include?(result)
      end

      def exact_password?
        [:exact_password, :exact_username_and_password].include?(result)
      end

      def similar_username_and_password?
        result == :similar_username_and_password
      end
    end
  end
end
