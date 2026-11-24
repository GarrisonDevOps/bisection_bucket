# frozen_string_literal: true

require 'base64'
require 'json'
require_relative 'azure_environment'
require_relative 'identity/default_credentials'

module AzIdentity
  # Adapts Azure identity credential acquisition to the credentials-provider
  # interface expected by redis-client / redis-rb:
  #
  #   provider.call        # => [username, password]
  #   provider.expires_at  # => Time or nil
  #
  # The password is a Microsoft Entra access token for the Azure Cache for
  # Redis scope. The username is the object (principal) ID of the managed
  # identity or service principal, taken from the token's +oid+ claim unless
  # an explicit +:username+ is supplied.
  class RedisCredentialsProvider
    include AzureEnvironment

    def initialize(options = {})
      @username = options[:username]
      @credential_client = options[:credential_client] || build_default_client(options)
      @mutex = Mutex.new
    end

    # Returns fresh [username, access_token]. Acquires or refreshes the token
    # as needed. Called by the Redis client on every (re)connect and before a
    # command whenever the token is close to expiring.
    def call
      credentials = @mutex.synchronize do
        @credentials = @credential_client.fetch_credentials_if_needed
      end

      raise Identity::BaseClient::FetchCredentialsError, 'no Azure credentials available for Redis' unless credentials

      [username(credentials.token), credentials.token]
    end

    # The Time at which the current token expires, so the Redis client can
    # re-authenticate long-lived connections before the token is rejected.
    def expires_at
      @mutex.synchronize { @credentials&.expires_at }
    end

    private

    def build_default_client(options)
      resource = options[:resource] || redis_resource(options[:environment])
      DefaultCredentials.new(options.merge(resource: resource))
    end

    def username(token)
      @username || object_id_from_token(token)
    end

    # Extracts the +oid+ (object ID) claim from the JWT access token without
    # verifying its signature. Azure Cache for Redis expects the AUTH username
    # to be the managed identity / service principal object ID.
    def object_id_from_token(token)
      payload = token.to_s.split('.')[1]
      return unless payload

      json = Base64.urlsafe_decode64(pad_base64(payload))
      JSON.parse(json)['oid']
    rescue ArgumentError, JSON::ParserError
      nil
    end

    def pad_base64(str)
      remainder = str.length % 4
      remainder.zero? ? str : str + ('=' * (4 - remainder))
    end
  end
end
