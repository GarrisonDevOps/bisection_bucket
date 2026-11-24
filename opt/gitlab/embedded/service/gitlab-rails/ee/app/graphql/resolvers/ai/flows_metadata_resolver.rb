# frozen_string_literal: true

module Resolvers
  module Ai
    # Backs the top-level `aiFlowsMetadata` query. See `::Ai::FlowsMetadataService`
    # for how the actual list of capabilities is computed.
    class FlowsMetadataResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      # Exposes `group`/`project` so `Types::Ai::FlowsMetadataType`'s
      # granular-token authorization directive can resolve its boundary
      # (group or project, falling back to instance-wide when neither a
      # namespace nor a project was given).
      Payload = Struct.new(:capabilities, :group, :project, keyword_init: true)

      type Types::Ai::FlowsMetadataType, null: false

      description 'Metadata describing Duo Agent Platform flow capabilities available to the caller.'

      argument :namespace_id, ::Types::GlobalIDType[::Namespace],
        required: false,
        description: 'Global ID of the group or personal namespace to compute flow capabilities for. ' \
          'When omitted, only namespace-independent capabilities are returned.'

      argument :project_id, ::Types::GlobalIDType[::Project],
        required: false,
        description: 'Global ID of the project to compute flow capabilities for. Takes precedence over ' \
          '`namespaceId` when both are given.'

      argument :client_type, ::Types::Ai::FlowsMetadata::ClientTypeEnum,
        required: false,
        description: 'Client surface making the request. Used to gate per-surface capabilities. ' \
          'When omitted, defaults to CLI behavior for backwards compatibility.'

      def resolve(namespace_id: nil, project_id: nil, client_type: nil)
        namespace = authorized_find_namespace!(namespace_id) if namespace_id
        project = authorized_find_project!(project_id) if project_id

        capabilities = ::Ai::FlowsMetadataService.new(
          current_user: current_user,
          namespace: namespace,
          project: project,
          client_type: client_type
        ).execute

        Payload.new(
          capabilities: capabilities,
          group: (namespace if namespace.is_a?(::Group)),
          project: project
        )
      end

      private

      # `authorized_find!` is avoided here and below because the authorization it runs is
      # hardcoded to the `api`/`read_api` scopes, which would reject the `ai_workflows`-only
      # tokens that duo-cli uses, even though this field explicitly permits that scope.
      def authorized_find_namespace!(namespace_id)
        namespace = Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(namespace_id))

        raise_resource_not_available_error! unless namespace &&
          Ability.allowed?(current_user, :read_namespace, namespace)

        namespace
      end

      def authorized_find_project!(project_id)
        project = Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(project_id))

        raise_resource_not_available_error! unless project && Ability.allowed?(current_user, :read_project, project)

        project
      end
    end
  end
end
