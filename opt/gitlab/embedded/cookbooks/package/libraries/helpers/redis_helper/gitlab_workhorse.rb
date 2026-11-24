module RedisHelper
  class GitlabWorkhorse < RedisHelper::Base
    def redis_params
      params = {
        url: redis_url.to_s,
        username: redis_credentials[:username],
        password: redis_credentials[:password],
        sentinels: sentinel_urls,
        sentinelMaster: master_name,
        sentinelUsername: redis_sentinels_username,
        sentinelPassword: redis_sentinels_password,
        sentinelTLS: redis_sentinels_ssl,
        sentinelTLSOptions: sentinel_tls_options,
        redisTLS: redis_tls_options
      }

      cp = workhorse_credentials_provider
      params[:credentialsProvider] = cp if cp
      params
    end

    private

    # Workhorse does not copy gitlab_rails Redis settings into its own node
    # attributes, so inherit the provider here (unset/nil inherits the global
    # one; false disables it). This keeps the base `credentials_provider?` guard
    # (which strips the identity/password from the Redis URL) consistent with
    # the rendered [redis.credentials_provider.azure] block.
    def redis_credentials_provider
      cp = super
      cp.nil? ? Gitlab['gitlab_rails']['redis_credentials_provider'] : cp
    end

    # Set once under gitlab_rails and inherited here unless overridden for
    # Workhorse. Renders as [redis.credentials_provider.azure] with the Go
    # SDK fields (auth_type, object_id, scope).
    def workhorse_credentials_provider
      cp = redis_credentials_provider
      return unless cp.is_a?(Hash) && !cp.empty?

      {
        'provider' => cp['provider'] || 'azure',
        'auth_type' => cp['auth_type'] || 'managed_identity',
        'object_id' => cp['object_id'] || redis_credentials[:username] || Gitlab['gitlab_rails']['redis_username'],
        'scope' => cp['scope'] || 'https://redis.azure.com/.default'
      }
    end

    def node_access_keys
      %w[gitlab gitlab_workhorse]
    end

    def support_sentinel_groupname?
      true
    end

    def sentinel_tls_options
      return unless redis_sentinels_ssl

      options = {}
      options[:certificate] = redis_sentinels_tls_client_cert_file if redis_sentinels_tls_client_cert_file
      options[:key] = redis_sentinels_tls_client_key_file if redis_sentinels_tls_client_key_file
      options[:ca_certificate] = redis_sentinels_tls_ca_cert_file if redis_sentinels_tls_ca_cert_file
      options
    end

    def redis_tls_options
      return unless redis_ssl

      options = {}
      options[:certificate] = redis_tls_client_cert_file if redis_tls_client_cert_file
      options[:key] = redis_tls_client_key_file if redis_tls_client_key_file
      options[:ca_certificate] = redis_tls_ca_cert_file if redis_tls_ca_cert_file
      options
    end

    def redis_tls_client_cert_file
      node_attr['redis_tls_client_cert_file']
    end

    def redis_tls_client_key_file
      node_attr['redis_tls_client_key_file']
    end

    def redis_tls_ca_cert_file
      node_attr['redis_tls_ca_cert_file']
    end
  end
end
