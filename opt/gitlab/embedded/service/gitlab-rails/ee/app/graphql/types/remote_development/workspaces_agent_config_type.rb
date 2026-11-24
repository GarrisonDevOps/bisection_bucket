# frozen_string_literal: true

module Types
  module RemoteDevelopment
    class WorkspacesAgentConfigType < ::Types::BaseObject
      graphql_name 'WorkspacesAgentConfig'
      description 'Represents a workspaces agent config'

      authorize :read_workspaces_agent_config

      field :id, ::Types::GlobalIDType[::RemoteDevelopment::WorkspacesAgentConfig],
        null: false, description: 'Global ID of the workspaces agent config.'

      field :cluster_agent, ::Types::Clusters::AgentType,
        null: false, description: 'Cluster agent that the workspaces agent config belongs to.'

      field :project_id, GraphQL::Types::ID,
        null: true, description: 'ID of the project that the workspaces agent config belongs to.'

      field :enabled, GraphQL::Types::Boolean,
        null: false, description: 'Indicates whether remote development is enabled for the GitLab agent.'

      field :dns_zone, GraphQL::Types::String,
        null: false, description: 'DNS zone where workspaces are available.'

      field :network_policy_enabled, GraphQL::Types::Boolean,
        null: false, description: 'Whether the network policy of the workspaces agent config is enabled.'

      field :gitlab_workspaces_proxy_namespace, GraphQL::Types::String,
        null: false, description: 'Namespace where gitlab-workspaces-proxy is installed.'

      field :workspaces_quota, GraphQL::Types::Int,
        null: false, description: 'Maximum number of workspaces for the GitLab agent.'

      field :workspaces_per_user_quota, GraphQL::Types::Int, # rubocop:disable GraphQL/ExtractType -- We don't want to extract this to a type, it's just an integer field
        null: false, description: 'Maximum number of workspaces per user.'

      field :allow_privilege_escalation, GraphQL::Types::Boolean,
        null: false, description: 'Allow privilege escalation.'

      field :use_kubernetes_user_namespaces, GraphQL::Types::Boolean,
        null: false, description: 'Indicates whether to use user namespaces in Kubernetes.'

      field :default_runtime_class, GraphQL::Types::String,
        null: false, description: 'Default Kubernetes RuntimeClass.'

      field :annotations, [::Types::RemoteDevelopment::KubernetesAnnotationType],
        null: false, description: 'Annotations to apply to Kubernetes objects.'

      field :labels, [::Types::RemoteDevelopment::KubernetesLabelType],
        null: false, description: 'Labels to apply to Kubernetes objects.'

      field :default_resources_per_workspace_container, ::Types::RemoteDevelopment::WorkspaceResourcesType, # rubocop:disable GraphQL/ExtractType -- We don't want to extract to a new type for backwards compatibility
        experiment: { milestone: '17.9' },
        null: false, description: 'Default cpu and memory resources of the workspace container.'

      field :max_resources_per_workspace, ::Types::RemoteDevelopment::WorkspaceResourcesType,
        experiment: { milestone: '17.9' },
        null: false, description: 'Maximum cpu and memory resources of the workspace.'

      field :network_policy_egress, [::Types::RemoteDevelopment::NetworkPolicyEgressType], # rubocop:disable GraphQL/ExtractType -- We don't want to extract to a new type for backwards compatibility
        experiment: { milestone: '17.9' },
        null: false, description: 'IP CIDR range specifications for egress destinations from a workspace.'

      field :image_pull_secrets, [::Types::RemoteDevelopment::ImagePullSecretsType],
        experiment: { milestone: '17.9' },
        null: false, description: 'Kubernetes secrets to pull private images for a workspace.'

      field :created_at, Types::TimeType,
        null: false, description: 'Timestamp of when the workspaces agent config was created.'

      field :updated_at, Types::TimeType, null: false,
        description: 'Timestamp of the last update to any mutable workspaces agent config property.'
    end
  end
end
