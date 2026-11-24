# frozen_string_literal: true

module RedisCloudAuth
  module Providers
    # Microsoft Entra provider. Thin adapter over the `az-identity` gem, which
    # already implements the provider interface (#call => [username, token],
    # #expires_at). The username defaults to the managed identity / service
    # principal object (principal) ID from the token's +oid+ claim.
    #
    # Descriptor keys: :username (optional), :resource (for example
    # "https://redis.azure.com"), :environment (optional Azure cloud).
    module Azure
      def self.build(descriptor)
        # Lazily required so az-identity is only pulled in when Azure is used.
        require "az_identity"

        AzIdentity::RedisCredentialsProvider.new(
          username: descriptor[:username],
          resource: descriptor[:resource],
          environment: descriptor[:environment]
        )
      end
    end
  end
end
