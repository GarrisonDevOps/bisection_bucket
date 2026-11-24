# frozen_string_literal: true

module Resolvers
  # rubocop: disable Gitlab/BoundedContexts -- this namespace is already established, embedding it deeper into another namespace would make things inconsistent.
  module PackageMetadata
    class AdvisoryResolver < BaseResolver
      include ::PackageMetadata::AdvisoryHelpers

      type Types::PackageMetadata::AdvisoryType, null: true

      argument :id, ::Types::GlobalIDType[::PackageMetadata::Advisory],
        required: false,
        description: 'Global ID of the advisory.'

      argument :identifier, ::GraphQL::Types::String,
        required: false,
        description: 'Identifier of the advisory.'

      def resolve(id: nil, identifier: nil)
        return unless current_user_allowed?(current_user)

        verify_rate_limit!

        if id.present?
          GitlabSchema.object_from_id(id, expected_type: ::PackageMetadata::Advisory)
        elsif identifier.present?
          ::PackageMetadata::Advisory.find_by_identifier(identifier)
        else
          raise Gitlab::Graphql::Errors::ArgumentError, 'At least one filter must be provided'
        end
      end

      private

      def verify_rate_limit!
        return unless Gitlab::ApplicationRateLimiter.throttled?(:package_metadata, scope: { user: current_user })

        raise_resource_not_available_error! ::Gitlab::ApplicationRateLimiter.throttled_error_message
      end
    end
  end
  # rubocop: enable Gitlab/BoundedContexts
end
