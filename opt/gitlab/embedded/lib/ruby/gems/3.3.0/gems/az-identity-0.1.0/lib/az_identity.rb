# frozen_string_literal: true

require_relative 'az_identity/identity/base_client'
require_relative 'az_identity/identity/credentials'
require_relative 'az_identity/identity/default_credentials'
require_relative 'az_identity/identity/managed_identity_client'
require_relative 'az_identity/identity/workload_identity_client'
require_relative 'az_identity/redis_credentials_provider'

module AzIdentity
  class << self
    def credentials(options = {})
      AzIdentity::DefaultCredentials.new(options).fetch_credentials_if_needed
    end

    # Builds a credentials provider suitable for authenticating to Azure Cache
    # for Redis with a Microsoft Entra token. Pass the result as the
    # +credentials_provider+ option to redis-client / redis-rb.
    def redis_credentials_provider(options = {})
      AzIdentity::RedisCredentialsProvider.new(options)
    end
  end
end
