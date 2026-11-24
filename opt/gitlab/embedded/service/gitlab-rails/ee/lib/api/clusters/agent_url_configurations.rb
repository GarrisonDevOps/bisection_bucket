# frozen_string_literal: true

module API
  module Clusters
    class AgentUrlConfigurations < ::API::Base
      before do
        authenticate!

        not_found! unless user_project.licensed_feature_available?(:cluster_receptive_agents)
        not_found! unless ::Gitlab::CurrentSettings.receptive_cluster_agents_enabled
      end

      feature_category :deployment_management

      helpers do
        def find_url_configuration(agent)
          cfg = agent.agent_url_configuration

          return unless cfg

          # NOTE: we currently only support a single url configuration for an agent.
          # However, this will change in future iterations when we want to support at least 2.
          return unless cfg.id == params[:url_configuration_id]

          cfg
        end
      end

      params do
        requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
      end
      resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
        params do
          requires :agent_id, type: Integer, desc: 'ID of the agent.'
        end
        resource ':id/cluster_agents/:agent_id' do
          resource :url_configurations do
            desc 'List all agent URL configurations' do
              detail 'Lists all agent URL configurations for a specified agent. You must have the Developer, ' \
                'Maintainer, or Owner role to use this endpoint. This feature was introduced in GitLab 17.4.'
              success Entities::Clusters::AgentUrlConfiguration
              is_array true
              tags %w[cluster_agents]
            end
            route_setting :tier, :ultimate
            route_setting :authorization, permissions: :read_cluster_agent_url_configuration, boundary_type: :project
            get do
              authorize! :admin_cluster, user_project

              agent = ::Clusters::AgentsFinder.new(user_project, current_user).find(params[:agent_id])

              not_found! unless agent

              url_cfg = agent.agent_url_configuration

              if url_cfg
                present [url_cfg], with: Entities::Clusters::AgentUrlConfiguration
              else
                []
              end
            end

            desc 'Retrieve an agent URL configuration' do
              detail 'Retrieves an agent URL configuration. You must have the Developer, Maintainer, or Owner ' \
                'role to use this endpoint. This feature was introduced in GitLab 17.4.'
              success Entities::Clusters::AgentUrlConfiguration
              tags %w[cluster_agents]
            end
            params do
              requires :url_configuration_id, type: Integer, desc: 'ID of the agent URL configuration.'
            end
            route_setting :tier, :ultimate
            route_setting :authorization, permissions: :read_cluster_agent_url_configuration, boundary_type: :project
            get ':url_configuration_id' do
              authorize! :admin_cluster, user_project

              agent = ::Clusters::AgentsFinder.new(user_project, current_user).find(params[:agent_id])

              not_found! unless agent

              url_cfg = find_url_configuration(agent)

              not_found! unless url_cfg

              present url_cfg, with: Entities::Clusters::AgentUrlConfiguration
            end

            desc 'Create an agent URL configuration' do
              detail 'Creates an agent URL configuration. You must have the Maintainer or Owner role to use this ' \
                'endpoint. An agent can have only one URL configuration at the time. This feature was introduced ' \
                'in GitLab 17.4.'
              success Entities::Clusters::AgentUrlConfiguration
              tags %w[cluster_agents]
            end
            params do
              requires :url, type: String, desc: 'Agent URL for this URL configuration.'
              optional :client_cert, type: String, desc: 'Client certificate in PEM format, used for mTLS ' \
                                                     'authentication. Must be provided with `client_key`.'
              optional :client_key, type: String, desc: 'Client key in PEM format, used for mTLS authentication. ' \
                                                    'Must be provided with `client_cert`.'
              optional :ca_cert, type: String,
                desc: 'CA certificate in PEM format used to verify the agent endpoint.'
              optional :tls_host, type: String, desc: 'TLS host name to verify the server name in the agent endpoint.'
            end
            route_setting :tier, :ultimate
            route_setting :authorization, permissions: :create_cluster_agent_url_configuration, boundary_type: :project
            post do
              authorize! :create_cluster, user_project

              agent = ::Clusters::AgentsFinder.new(user_project, current_user).find(params[:agent_id])

              not_found! unless agent

              url_cfg_params = declared_params(include_missing: false)
              result = ::Clusters::Agents::CreateUrlConfigurationService.new(
                agent: agent,
                current_user: current_user,
                params: url_cfg_params
              ).execute

              bad_request!(result[:message]) if result[:status] == :error

              present result[:url_configuration], with: Entities::Clusters::AgentUrlConfiguration
            end

            desc 'Delete an agent URL configuration' do
              detail 'Deletes an agent URL configuration. You must have the Maintainer or Owner role to use this ' \
                'endpoint. This feature was introduced in GitLab 17.4.'
              success code: 204, message: 'Resource deleted'
              tags %w[cluster_agents]
            end
            params do
              requires :url_configuration_id, type: Integer, desc: 'ID of the agent URL configuration.'
            end
            route_setting :tier, :ultimate
            route_setting :authorization, permissions: :delete_cluster_agent_url_configuration, boundary_type: :project
            delete ':url_configuration_id' do
              authorize! :admin_cluster, user_project

              agent = ::Clusters::AgentsFinder.new(user_project, current_user).find(params[:agent_id])

              not_found! unless agent

              url_cfg = find_url_configuration(agent)

              not_found! unless url_cfg

              destroy_conditionally!(url_cfg) do |url_cfg|
                ::Clusters::Agents::DeleteUrlConfigurationService
                  .new(agent: agent, current_user: current_user, url_configuration: url_cfg)
                  .execute
              end
            end
          end
        end
      end
    end
  end
end
