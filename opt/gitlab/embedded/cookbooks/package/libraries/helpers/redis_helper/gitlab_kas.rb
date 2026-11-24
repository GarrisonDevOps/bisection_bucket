module RedisHelper
  class GitlabKAS < RedisHelper::Base
    def redis_params
      params = {
        network: redis_network,
        address: redis_address,
        username: redis_credentials[:username],
        password: redis_credentials[:password],
        sentinels: redis_sentinels,
        sentinelMaster: master_name,
        sentinelPassword: redis_sentinels_password,
        ssl: redis_ssl
      }

      cp = kas_credentials_provider
      params[:credentialsProvider] = cp if cp
      params
    end

    private

    # Renders as redis.server.credentials_provider.azure (auth_type, object_id,
    # scope). Inherited from gitlab_rails via parse_redis_settings unless set.
    def kas_credentials_provider
      # A Hash enables it; nil (unset, inherited from gitlab_rails via
      # parse_redis_settings) or false (explicitly disabled) means off.
      cp = redis_credentials_provider
      return unless cp.is_a?(Hash) && !cp.empty?

      {
        'provider' => cp['provider'] || 'azure',
        'auth_type' => cp['auth_type'] || 'managed_identity',
        'object_id' => cp['object_id'] || redis_credentials[:username],
        'scope' => cp['scope'] || 'https://redis.azure.com/.default'
      }
    end

    def redis_network
      redis_url.scheme == 'unix' ? 'unix' : 'tcp'
    end

    def redis_address
      redis_network == 'tcp' ? "#{redis_host}:#{redis_port || URI::Redis::DEFAULT_PORT}" : redis_socket
    end

    def master_name
      node_attr['redis_sentinels_master_name']
    end

    def node_access_keys
      %w[gitlab_kas]
    end

    def support_sentinel_groupname?
      true
    end
  end
end
