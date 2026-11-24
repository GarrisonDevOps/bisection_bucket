# frozen_string_literal: true

module Types
  module RemoteDevelopment
    class WorkspaceType < ::Types::BaseObject
      graphql_name 'Workspace'
      description 'Represents a remote development workspace'

      authorize :read_workspace

      field :id, ::Types::GlobalIDType[::RemoteDevelopment::Workspace],
        null: false, description: 'Global ID of the workspace.'

      field :cluster_agent, ::Types::Clusters::AgentType,
        null: false,
        method: :agent,
        description: 'Kubernetes agent associated with the workspace.'

      field :project_id, GraphQL::Types::ID,
        null: false, description: 'ID of the project that contains the devfile for the workspace.'

      field :user, ::Types::UserType,
        null: false, description: 'Owner of the workspace.'

      field :name, GraphQL::Types::String,
        null: false, description: 'Name of the workspace in Kubernetes.'

      field :namespace, GraphQL::Types::String,
        null: false, description: 'Namespace of the workspace in Kubernetes.'

      # TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/409772 - Make this a type:enum
      field :desired_state, GraphQL::Types::String,
        null: false, description: 'Desired state of the workspace.'

      field :desired_state_updated_at, Types::TimeType, # rubocop:disable GraphQL/ExtractType -- We don't want to extract this to a type
        null: false, description: 'Timestamp of the last update to the desired state.'

      # TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/409772 - Make this a type:enum
      field :actual_state, GraphQL::Types::String,
        null: false, description: 'Actual state of the workspace.'

      field :actual_state_updated_at, Types::TimeType, # rubocop:disable GraphQL/ExtractType -- We don't want to extract this to a type
        experiment: { milestone: '17.11' },
        null: false, description: 'Timestamp of the last update to the actual state.'

      field :responded_to_agent_at, Types::TimeType,
        null: true,
        description: 'Timestamp of the last response sent to the GitLab agent for Kubernetes for the workspace.'

      field :url, GraphQL::Types::String,
        null: false, description: 'URL of the workspace.'

      # TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/498322 - Remove in 18.0
      field :editor, GraphQL::Types::String,
        null: false,
        description: 'Editor used to configure the workspace. Must match a configured template.',
        deprecated: { reason: 'Field is not used', milestone: '17.5' }

      field :max_hours_before_termination, GraphQL::Types::Int,
        null: false,
        description: 'Number of hours until the workspace automatically terminates.',
        deprecated: { reason: 'Field is not used', milestone: '17.9' }

      # TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/510078 - Remove in 19.0
      field :devfile_ref, GraphQL::Types::String,
        null: false, description: 'Git reference that contains the devfile used to configure the workspace.',
        deprecated: { reason: 'Field is renamed to project_ref', milestone: '17.8' }, method: :project_ref

      field :project_ref, GraphQL::Types::String, # rubocop:disable GraphQL/ExtractType -- We don't want to extract this to a type
        null: false, description: 'Git reference that contains the devfile used to configure the workspace, ' \
                       'and that will be cloned into the workspace'

      field :devfile_path, GraphQL::Types::String,
        null: true, description: 'Path to the devfile used to configure the workspace.'

      # TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/503465 - Remove in 19.0
      field :devfile_web_url, GraphQL::Types::String, # rubocop:disable GraphQL/ExtractType -- We don't want to extract this to a type, it would cause confusion with the devfile field
        null: true, description: 'Web URL of the devfile used to configure the workspace.',
        deprecated: { reason: 'Field is not used', milestone: '17.8' }

      field :devfile, GraphQL::Types::String,
        null: false, description: 'Source YAML of the devfile used to configure the workspace.'

      field :processed_devfile, GraphQL::Types::String,
        null: false, description: 'Processed YAML of the devfile used to configure the workspace.'

      field :deployment_resource_version, GraphQL::Types::Int,
        null: true, description: 'Version of the deployment resource for the workspace.'

      field :workspaces_agent_config_version, GraphQL::Types::Int,
        experiment: { milestone: '17.6' },
        null: false, description: 'Version of the associated WorkspacesAgentConfig for the workspace.'

      field :force_include_all_resources, GraphQL::Types::Boolean,
        experiment: { milestone: '17.6' },
        null: false,
        description: 'Forces all resources to be included for the workspace' \
          'during the next reconciliation with the agent.'

      field :created_at, Types::TimeType,
        null: false, description: 'Timestamp of when the workspace was created.'

      field :updated_at, Types::TimeType,
        null: false, description: 'Timestamp of the last update to any mutable workspace property.'

      field :workspace_variables,
        ::Types::RemoteDevelopment::WorkspaceVariableType.connection_type,
        null: true,
        experiment: { milestone: '17.9' },
        description: 'User defined variables associated with the workspace.', method: :user_provided_workspace_variables

      # @return [String]
      def project_id
        "gid://gitlab/Project/#{object.project_id}"
      end

      # @return [String]
      def editor
        'webide'
      end

      # @return [Integer]
      def max_hours_before_termination
        ::RemoteDevelopment::WorkspaceOperations::MaxHoursBeforeTermination::MAX_HOURS_BEFORE_TERMINATION
      end
    end
  end
end
