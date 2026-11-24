# frozen_string_literal: true

module Mutations
  module Govern
    # Shared by every policy store mutation: the container arguments and the
    # lookup behind authorized_find!, plus the fallback for service reasons the
    # mutation does not map. Which reasons are user-facing stays in each
    # mutation's resolve.
    module PolicyStoreMutation
      extend ActiveSupport::Concern

      UnmappedReasonError = Class.new(StandardError)

      UNMAPPED_REASON_MESSAGE = 'Could not complete the policy store request'

      CONTAINER_ARGUMENTS = %i[organization_id group_path].freeze

      included do
        argument :organization_id, ::Types::GlobalIDType[::Organizations::Organization],
          required: false,
          description: 'Global ID of the organization whose policy store to use. ' \
            'Exactly one of `organizationId` or `groupPath` is required.'

        argument :group_path, GraphQL::Types::ID,
          required: false,
          description: 'Full path of the group whose policy store to use. ' \
            'Exactly one of `organizationId` or `groupPath` is required.'

        validates exactly_one_of: CONTAINER_ARGUMENTS
      end

      private

      # Mirror the policies resolver: track the unmapped reason and surface a generic
      # error rather than rendering an internal service message as user error.
      def track_unmapped_reason!(response)
        ::Gitlab::ErrorTracking.track_exception(
          UnmappedReasonError.new(
            "Unmapped policy store reason: #{response.reason} (#{self.class.graphql_name})"
          ),
          service_message: response.message
        )

        raise GraphQL::ExecutionError, UNMAPPED_REASON_MESSAGE
      end

      # A missing or blank group path resolves to nil so authorized_find! answers with
      # the same access error as an unauthorized one: probing paths leaks nothing.
      def find_object(organization_id: nil, group_path: nil)
        return ::Group.find_by_full_path(group_path) unless group_path.nil?

        ::GitlabSchema.object_from_id(organization_id, expected_type: ::Organizations::Organization).sync
      end
    end
  end
end
