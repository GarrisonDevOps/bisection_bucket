# frozen_string_literal: true

module Resolvers
  # rubocop: disable Gitlab/BoundedContexts -- this namespace is already established, embedding it deeper into another namespace would make things inconsistent.
  module PackageMetadata
    class AdvisoriesResolver < BaseResolver
      include ::PackageMetadata::AdvisoryHelpers
      include LooksAhead

      MAX_IDENTIFIERS = 500

      type Types::PackageMetadata::AdvisoryType.connection_type, null: true

      authorize_granular_token permissions: :read_metadata, boundary: :instance, boundary_type: :instance

      argument :identifiers, [::GraphQL::Types::String],
        required: true,
        description: 'Array of advisory identifiers.'

      argument :created_after, ::GraphQL::Types::ISO8601DateTime,
        required: false,
        description: 'Filter advisories created after the datetime.'

      argument :updated_after, ::GraphQL::Types::ISO8601DateTime,
        required: false,
        description: 'Filter advisories updated after the datetime.'

      def resolve_with_lookahead(identifiers:, created_after: nil, updated_after: nil)
        return unless current_user_allowed?(current_user)

        identifiers = identifiers.reject(&:blank?)

        return offset_pagination(::PackageMetadata::Advisory.none) if identifiers.empty?

        if identifiers.size > MAX_IDENTIFIERS
          raise Gitlab::Graphql::Errors::ArgumentError,
            "Too many identifiers. Maximum is #{MAX_IDENTIFIERS}."
        end

        verify_rate_limit!

        advisories = ::PackageMetadata::AdvisoriesFinder.new(
          identifiers: identifiers,
          created_after: created_after,
          updated_after: updated_after
        ).execute

        offset_pagination(apply_lookahead(advisories))
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
