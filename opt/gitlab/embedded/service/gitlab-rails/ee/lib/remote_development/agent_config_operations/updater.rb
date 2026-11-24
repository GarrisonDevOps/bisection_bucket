# frozen_string_literal: true

module RemoteDevelopment
  module AgentConfigOperations
    class Updater
      include Messages

      # @param [Hash] context
      # @return [Gitlab::Fp::Result]
      def self.update(context)
        context => { agent: Clusters::Agent => agent, config: Hash => raw_config_from_params, logger: logger }
        config = raw_config_from_params.deep_symbolize_keys
        config_from_agent_config_file = config[:remote_development]

        unless config_from_agent_config_file
          return Gitlab::Fp::Result.ok(
            AgentConfigUpdateSkippedBecauseNoConfigFileEntryFound.new({ skipped_reason: :no_config_file_entry_found })
          )
        end

        workspaces_agent_config = update_or_initialize_workspaces_agent_config(
          agent: agent,
          config_from_agent_config_file: config_from_agent_config_file
        )

        model_errors = workspaces_agent_config.errors unless workspaces_agent_config.save

        if model_errors.present?
          logger.warn(
            message: "Failed to save agent configuration file",
            agent_id: agent.id,
            error: model_errors.full_messages.join(', ')
          )
          return Gitlab::Fp::Result.err(AgentConfigUpdateFailed.new({ errors: model_errors }))
        end

        Gitlab::Fp::Result.ok(
          AgentConfigUpdateSuccessful.new({ workspaces_agent_config: workspaces_agent_config })
        )
      end

      # @param [Clusters::Agent] agent
      # @param [Hash] config_from_agent_config_file
      # @return [RemoteDevelopment::WorkspacesAgentConfig]
      def self.update_or_initialize_workspaces_agent_config(agent:, config_from_agent_config_file:)
        agent_config_model_instance = WorkspacesAgentConfig.find_or_initialize_by(agent: agent) # rubocop:disable CodeReuse/ActiveRecord -- We don't want to use a finder, we want to use find_or_initialize_by because it's more concise

        normalized_config_from_file = config_from_agent_config_file.dup.to_h.transform_keys(&:to_sym)

        # NOTE: In the agent config file, the `namespace` is nested under `gitlab_workspaces_proxy`, but in the database
        #       it is a single `gitlab_workspaces_proxy_namespace`, not a jsonb field for `gitlab_workspaces_proxy`.
        #       So, in order to do the `merge` below of config_from_agent_config_file into agent_config_settings,
        #       we will make the config_from_agent_config_file match the single field name.
        #       The same is true for other fields nested under `gitlab_workspaces_proxy` - `http_enabled`, `ssh_enabled`
        proxy_namespace = normalized_config_from_file.dig(:gitlab_workspaces_proxy, :namespace)
        normalized_config_from_file[:gitlab_workspaces_proxy_namespace] = proxy_namespace if proxy_namespace

        proxy_http_enabled = normalized_config_from_file.dig(:gitlab_workspaces_proxy, :http_enabled)
        unless proxy_http_enabled.nil?
          normalized_config_from_file[:gitlab_workspaces_proxy_http_enabled] = proxy_http_enabled
        end

        proxy_ssh_enabled = normalized_config_from_file.dig(:gitlab_workspaces_proxy, :ssh_enabled)
        unless proxy_ssh_enabled.nil?
          normalized_config_from_file[:gitlab_workspaces_proxy_ssh_enabled] = proxy_ssh_enabled
        end
        #       Same for `network_policy_enabled` and `network_policy_egress` db fields - rename them from the
        #       network_policy field in the config_from_agent_config_file spec
        network_policy_enabled = normalized_config_from_file.dig(:network_policy, :enabled)
        normalized_config_from_file[:network_policy_enabled] = network_policy_enabled unless network_policy_enabled.nil?
        network_policy_egress = normalized_config_from_file.dig(:network_policy, :egress)
        normalized_config_from_file[:network_policy_egress] = network_policy_egress if network_policy_egress

        # NOTE: `enabled` is the one field we can't easily move into the Settings module, so its default
        #       remains hardcoded here. It may also be a string or a boolean.
        normalized_config_from_file[:enabled] = ["true", true].include?(normalized_config_from_file[:enabled])

        # NOTE: We rely on the settings module to fetch the defaults of all values except `enabled` in the
        #       agent config file. This is temporary pending completion of the settings module/UI which will
        #       remove the dependence on the agent config file for these values.

        agent_config_settings = Settings.get(
          [
            :allow_privilege_escalation,
            :annotations,
            :default_resources_per_workspace_container,
            :default_runtime_class,
            :dns_zone,
            :gitlab_workspaces_proxy_http_enabled,
            :gitlab_workspaces_proxy_namespace,
            :gitlab_workspaces_proxy_ssh_enabled,
            :image_pull_secrets,
            :labels,
            :max_active_hours_before_stop,
            :max_resources_per_workspace,
            :max_stopped_hours_before_termination,
            :network_policy_egress,
            :network_policy_enabled,
            :use_kubernetes_user_namespaces,
            :workspaces_per_user_quota,
            :workspaces_quota,
            :shared_namespace
          ]
        )
        values = agent_config_settings.merge(normalized_config_from_file)

        set_attributes_on_agent_config_model_instance(
          agent_config_model: agent_config_model_instance,
          values: values,
          agent_model: agent
        )

        agent_config_model_instance
      end

      # @param [WorkspacesAgentConfig] agent_config_model
      # @param [Hash] values
      # @param [Clusters::Agent] agent_model
      # @return [RemoteDevelopment::WorkspacesAgentConfig]
      # noinspection RubyResolve -- https://handbook.gitlab.com/handbook/tools-and-tips/editors-and-ides/jetbrains-ides/tracked-jetbrains-issues/#ruby-32301
      def self.set_attributes_on_agent_config_model_instance(agent_config_model:, values:, agent_model:)
        agent_config_model.assign_attributes({
          allow_privilege_escalation: values[:allow_privilege_escalation],
          annotations: values[:annotations],
          default_resources_per_workspace_container: values[:default_resources_per_workspace_container],
          default_runtime_class: values[:default_runtime_class],
          dns_zone: values[:dns_zone],
          enabled: values[:enabled],
          gitlab_workspaces_proxy_http_enabled: values[:gitlab_workspaces_proxy_http_enabled],
          gitlab_workspaces_proxy_namespace: values[:gitlab_workspaces_proxy_namespace],
          gitlab_workspaces_proxy_ssh_enabled: values[:gitlab_workspaces_proxy_ssh_enabled],
          image_pull_secrets: values[:image_pull_secrets],
          labels: values[:labels],
          max_active_hours_before_stop: values[:max_active_hours_before_stop],
          max_resources_per_workspace: values[:max_resources_per_workspace],
          max_stopped_hours_before_termination: values[:max_stopped_hours_before_termination],
          network_policy_egress: values[:network_policy_egress],
          network_policy_enabled: values[:network_policy_enabled],
          project_id: agent_model.project_id,
          use_kubernetes_user_namespaces: values[:use_kubernetes_user_namespaces],
          workspaces_per_user_quota: values[:workspaces_per_user_quota],
          workspaces_quota: values[:workspaces_quota],
          shared_namespace: values[:shared_namespace]
        })
      end

      private_class_method :update_or_initialize_workspaces_agent_config, :set_attributes_on_agent_config_model_instance
    end
  end
end
