# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    # NOTE: If any changes are made to the URL structure, ensure the same is reflected in
    #       `ee/lib/remote_development/workspaces_server_operations/authorize_user_access/workspace_host_parser.rb`.
    class WorkspaceUrlHelper
      # @return [String]
      def self.url_template(name, dns_zone, gitlab_workspaces_proxy_http_enabled)
        "${PORT}-#{name}.#{workspace_host_suffix(dns_zone, gitlab_workspaces_proxy_http_enabled)}"
      end

      # @return [String]
      def self.url(url_prefix, url_query_string, dns_zone, gitlab_workspaces_proxy_http_enabled)
        host = "#{url_prefix}.#{workspace_host_suffix(dns_zone, gitlab_workspaces_proxy_http_enabled)}"
        hostname, _, port = host.rpartition(":")
        args = if Integer(port, exception: false).nil?
                 { host: host, query: url_query_string, path: "/" }
               else
                 { host: hostname, port: port, query: url_query_string, path: "/" }
               end

        URI::HTTPS.build(**args).to_s
      end

      # @return [Boolean]
      def self.common_workspace_host_suffix?(gitlab_workspaces_proxy_http_enabled)
        gitlab_config_workspaces_enabled? && !gitlab_workspaces_proxy_http_enabled
      end

      # @return [String]
      def self.workspace_host_suffix(dns_zone, gitlab_workspaces_proxy_http_enabled)
        if common_workspace_host_suffix?(gitlab_workspaces_proxy_http_enabled)
          # We can safely assume these values are set properly because we do that in the initializers.
          Gitlab.config.workspaces.host
        else
          dns_zone
        end
      end

      def self.gitlab_config_workspaces_enabled?
        # We can safely assume these values are set properly because we do that in the initializers.
        Gitlab.config.workspaces.enabled
      end

      private_class_method :gitlab_config_workspaces_enabled?
    end
  end
end
