# frozen_string_literal: true

module Mutations
  module RemoteDevelopment
    module WorkspaceOperations
      class Update < BaseMutation
        graphql_name 'WorkspaceUpdate'

        include Gitlab::Utils::UsageData

        authorize :update_workspace
        authorize_granular_token permissions: :update_workspace, boundary_argument: :id,
          boundary: :project, boundary_type: :project

        field :workspace,
          Types::RemoteDevelopment::WorkspaceType,
          null: true,
          description: 'Created workspace.'

        argument :id, ::Types::GlobalIDType[::RemoteDevelopment::Workspace],
          required: true,
          description: copy_field_description(Types::RemoteDevelopment::WorkspaceType, :id)

        # TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/409772 - Make this a type:enum
        argument :desired_state,
          GraphQL::Types::String,
          required: true, # NOTE: This is required, because it is the only mutable field.
          description: 'Desired state of the created workspace.'

        # @param [GlobalID] id
        # @param [Hash] args
        # @return [Hash]
        def resolve(id:, **args)
          unless License.feature_available?(:remote_development)
            raise_resource_not_available_error!("'remote_development' licensed feature is not available")
          end

          workspace = authorized_find!(id: id)

          # noinspection RubyNilAnalysis - This is because the superclass #current_user uses #[], which can return nil
          # TODO: Change the superclass to use context.fetch(:current_user) instead of context[:current_user]
          track_usage_event(:users_updating_workspaces, current_user.id)

          domain_main_class_args = {
            user: current_user,
            workspace: workspace,
            params: args
          }

          response = ::RemoteDevelopment::CommonService.execute(
            domain_main_class: ::RemoteDevelopment::WorkspaceOperations::Update::Main,
            domain_main_class_args: domain_main_class_args
          )

          response_object = response.success? ? response.payload[:workspace] : nil

          {
            workspace: response_object,
            errors: response.errors
          }
        end
      end
    end
  end
end
