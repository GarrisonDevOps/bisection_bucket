# frozen_string_literal: true

require 'json'

module Fog
  module AzureRM
    module Identity
      # WorkflowIdentityClient attempts to fetch credentials for Azure Workflow Identity
      # via the following environment variables:
      #
      # - AZURE_AUTHORITY_HOST - This can be used to override the default authority URL.
      # - AZURE_TENANT_ID
      # - AZURE_CLIENT_ID
      # - AZURE_FEDERATED_TOKEN_FILE - This is a filename that stores the JWT token that
      #   is exchanged for an OAuth2 token.
      class WorkflowIdentityClient < BaseClient
        include Fog::AzureRM::Utilities::General

        attr_accessor :environment, :resource, :authority, :tenant_id, :client_id, :token_file

        def initialize(options)
          super()
          @environment = options[:environment]
          @resource = storage_resource(@environment)
          @authority = ENV['AZURE_AUTHORITY_HOST'] || authority_url(@environment)
          @tenant_id = ENV['AZURE_TENANT_ID']
          @client_id = ENV['AZURE_CLIENT_ID']
          @token_file = ENV['AZURE_FEDERATED_TOKEN_FILE']

          normalize_authority!
        end

        def fetch_credentials
          return unless authority && tenant_id && client_id
          return unless ::File.exist?(token_file) && ::File.readable?(token_file)

          oidc_token = ::File.read(token_file)
          token_url = "#{authority}/#{tenant_id}/oauth2/v2.0/token"
          scope = "#{storage_resource(@environment)}/.default"

          data = {
            client_id: client_id,
            grant_type: 'client_credentials',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: oidc_token,
            scope: scope
          }

          response = post(token_url, body: data)

          process_token_response(response)
        rescue ::Faraday::Error => e
          raise FetchCredentialsError, e.to_s
        end

        private

        # The Azure Python SDK handles an authority with or without a scheme, so let's
        # do this too: https://github.com/Azure/azure-sdk-for-python/pull/11050
        def normalize_authority!
          parsed = URI.parse(authority)

          unless parsed.scheme
            @authority = "https://#{authority.strip.chomp('/')}"
            return
          end

          # rubocop:disable Style/IfUnlessModifier
          unless parsed.scheme == 'https'
            raise ArgumentError, "'#{authority}' is an invalid authority. The value must be a TLS protected (https) URL."
          end
          # rubocop:enable Style/IfUnlessModifier

          @authority = authority.strip.chomp('/')
        end
      end
    end
  end
end
