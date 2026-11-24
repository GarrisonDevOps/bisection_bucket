# frozen_string_literal: true

module RemoteDevelopment
  module Settings
    class DefaultSettings
      include Files
      include RemoteDevelopmentConstants

      UNDEFINED = nil

      # ALL REMOTE DEVELOPMENT SETTINGS MUST BE DECLARED HERE.
      # See ../README.md for more details.
      # @return [Hash]
      def self.default_settings
        {
          allow_privilege_escalation: [false, :Boolean],
          annotations: [{}, Hash],
          # NOTE: default_branch_name is not actually used by Remote Development, it is simply a placeholder to drive
          #       the logic for reading settings from ::Gitlab::CurrentSettings. It can be replaced when there is an
          #       actual Remote Development entry in ::Gitlab::CurrentSettings.
          default_branch_name: [UNDEFINED, String],
          default_devfile_yaml: [
            format(DEFAULT_DEVFILE_YAML, schema_version: REQUIRED_DEVFILE_SCHEMA_VERSION), String
          ],
          default_resources_per_workspace_container: [{}, Hash],
          default_runtime_class: ["", String],
          dns_zone: ["", String],
          full_reconciliation_interval_seconds: [3600, Integer],
          gitlab_kas_external_url: ["", String],
          gitlab_workspaces_proxy_http_enabled: [true, :Boolean],
          gitlab_workspaces_proxy_namespace: ["gitlab-workspaces", String],
          gitlab_workspaces_proxy_ssh_enabled: [true, :Boolean],
          image_pull_secrets: [[], Array],
          labels: [{}, Hash],
          max_active_hours_before_stop: [36, Integer],
          max_resources_per_workspace: [{}, Hash],
          max_stopped_hours_before_termination: [744, Integer],
          network_policy_egress: [[{
            allow: "0.0.0.0/0",
            except: %w[10.0.0.0/8 172.16.0.0/12 192.168.0.0/16]
          }], Array],
          network_policy_enabled: [true, :Boolean],
          partial_reconciliation_interval_seconds: [10, Integer],
          shared_namespace: ["", String],
          tools_injector_image: [
            RemoteDevelopment::WorkspaceOperations::WorkspaceOperationsConstants::WORKSPACE_TOOLS_IMAGE, String
          ],
          use_kubernetes_user_namespaces: [false, :Boolean],
          workspaces_per_user_quota: [-1, Integer],
          workspaces_quota: [-1, Integer]
        }
      end
    end
  end
end
