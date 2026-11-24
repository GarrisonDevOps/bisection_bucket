# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class CurrentUserAccessResolver < ::Resolvers::BaseResolver
      include ::Gitlab::Graphql::Authorize::AuthorizeResource
      include ::ArtifactRegistry::ResolvesOnRepository

      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      type ::Types::ArtifactRegistry::CurrentUserAccessType, null: true

      def resolve
        result = ::ArtifactRegistry::CurrentUserAccessService.new(
          current_user: current_user,
          organization: artifact_registry_organization
        ).execute

        raise_lookup_error!(result) if result.error?

        result.payload
      end

      private

      def raise_lookup_error!(result)
        code = RoleAssignmentsResolver::ERROR_CODES.fetch(result.reason, 'unknown')

        raise_resource_not_available_error!(result.message, { code: code })
      end
    end
  end
end
