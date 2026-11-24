# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class WorkspaceVariablesCreator
        include Messages

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.create(context)
          context => {
            workspace: RemoteDevelopment::Workspace => workspace,
            personal_access_token: PersonalAccessToken => personal_access_token,
            user: User => user,
            vscode_extension_marketplace: Hash => vscode_extension_marketplace,
            params: Hash => params,
            settings: {
              gitlab_kas_external_url: gitlab_kas_external_url
            }
          }
          params => {
            variables: Array => user_provided_variables
          }
          # When we have the ability to define variables for workspaces
          # at project/group/instance level, add them here.
          variables = user_provided_variables
          workspace_name = workspace.name
          dns_zone = workspace.workspaces_agent_config.dns_zone
          gitlab_workspaces_proxy_http_enabled = workspace.workspaces_agent_config.gitlab_workspaces_proxy_http_enabled
          domain_template = RemoteDevelopment::WorkspaceOperations::WorkspaceUrlHelper.url_template(
            workspace_name,
            dns_zone,
            gitlab_workspaces_proxy_http_enabled
          )
          # To keep things simple, we always inject the workspace token. It's value will only be set if required.
          # Else, it will be an empty string.
          workspace_token = ""
          if WorkspaceOperations::WorkspaceUrlHelper.common_workspace_host_suffix?(gitlab_workspaces_proxy_http_enabled)
            workspace_token = workspace.workspace_token.token
          end

          workspace_variables = WorkspaceVariablesBuilder.build(
            domain_template: domain_template,
            gitlab_kas_external_url: gitlab_kas_external_url,
            personal_access_token_value: personal_access_token.token,
            user_name: user.name,
            user_email: user.email,
            workspace_id: workspace.id,
            workspace_token: workspace_token,
            vscode_extension_marketplace: vscode_extension_marketplace,
            variables: variables
          )

          workspace_variables.each do |workspace_variable_params|
            workspace_variable = RemoteDevelopment::WorkspaceVariable.new(workspace_variable_params)
            workspace_variable.save

            if workspace_variable.errors.present?
              return Gitlab::Fp::Result.err(
                WorkspaceVariablesModelCreateFailed.new({ errors: workspace_variable.errors, context: context })
              )
            end
          end

          Gitlab::Fp::Result.ok(context)
        end
      end
    end
  end
end
