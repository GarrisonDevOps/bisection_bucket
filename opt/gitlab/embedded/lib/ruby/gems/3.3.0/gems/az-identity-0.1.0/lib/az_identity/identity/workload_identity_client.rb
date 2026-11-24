# frozen_string_literal: true

require 'json'
require 'faraday'
require_relative 'base_client'

module AzIdentity
  module Identity
    class WorkloadIdentityClient < BaseClient
      attr_accessor :environment, :resource, :authority, :tenant_id, :client_id, :token_file

      def initialize(options = {})
        super()
        @environment = options[:environment]
        @resource = options[:resource] || storage_resource(@environment)
        @authority = ENV['AZURE_AUTHORITY_HOST'] || authority_url(@environment)
        @tenant_id = ENV.fetch('AZURE_TENANT_ID', nil)
        @client_id = ENV.fetch('AZURE_CLIENT_ID', nil)
        @token_file = ENV.fetch('AZURE_FEDERATED_TOKEN_FILE', nil)

        normalize_authority!
      end

      def fetch_credentials
        return unless federated_credentials_available?

        response = post(token_endpoint, body: token_request_body)
        process_token_response(response)
      rescue ::Faraday::Error => e
        raise FetchCredentialsError, e.to_s
      end

      private

      def federated_credentials_available?
        return false unless authority && tenant_id && client_id && token_file

        ::File.exist?(token_file) && ::File.readable?(token_file)
      end

      def token_endpoint
        "#{authority}/#{tenant_id}/oauth2/v2.0/token"
      end

      def token_request_body
        {
          client_id: client_id,
          grant_type: 'client_credentials',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: ::File.read(token_file),
          scope: "#{resource}/.default"
        }
      end

      def normalize_authority!
        parsed = URI.parse(authority)

        unless parsed.scheme
          @authority = "https://#{authority.strip.chomp('/')}"
          return
        end

        unless parsed.scheme == 'https'
          raise ArgumentError,
                "'#{authority}' is an invalid authority. The value must be a TLS protected (https) URL."
        end

        @authority = authority.strip.chomp('/')
      end
    end
  end
end
