# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    # Reads Artifact Registry role assignments through
    # LookupRoleAssignmentsService and surfaces IAM's keyset pagination as a
    # Relay connection, carrying its opaque page_token as the cursor.
    class RoleAssignmentsResolver < ::Resolvers::BaseResolver
      include ::Gitlab::Graphql::Authorize::AuthorizeResource

      type ::Types::ArtifactRegistry::RoleAssignmentType.connection_type, null: true

      # The page fetched from IAM must be the page the connection renders:
      # the connection cuts nodes at the field's max_page_size while the end
      # cursor comes from IAM, so fetching more than we render would silently
      # drop the difference. This bounds both sides to the same number.
      MAX_PAGE_SIZE = 100

      ERROR_CODES = {
        permission_denied: 'denied',
        not_found: 'denied',
        signed_out: 'denied',
        unavailable: 'unavailable',
        timeout: 'unavailable',
        unauthenticated: 'unavailable',
        invalid_request: 'invalid_request'
      }.freeze

      argument :resource_ids, [GraphQL::Types::String],
        required: false,
        default_value: [],
        description: 'UUIDs of the Artifact Registry resources to read role assignments for. ' \
          'Empty reads the whole organization, which only the organization owner may do.'

      argument :roles, [::Types::ArtifactRegistry::RoleEnum],
        required: false,
        default_value: [],
        description: 'Only return assignments for these roles.'

      MAX_ASSIGNEES = 20

      argument :assignee_ids, [::Types::GlobalIDType[::User]],
        required: false,
        default_value: [],
        validates: { length: { maximum: MAX_ASSIGNEES } },
        prepare: ->(global_ids, _ctx) { global_ids.map(&:model_id) },
        description: "Global IDs of users to read direct role assignments on repositories for, at most " \
          "#{MAX_ASSIGNEES}. Cannot be combined with `resourceIds`. The organization owner and admins of the " \
          'Artifact Registry namespace may use it.'

      # first/after drive IAM's page_size/page_token. Keyset paging is
      # forward-only, so the field mounts the forward-only connection
      # extension and last/before do not exist on the schema.
      def resolve(resource_ids:, roles:, assignee_ids:, first: nil, after: nil)
        unless current_user
          raise_resource_not_available_error!(RESOURCE_ACCESS_ERROR, { code: ERROR_CODES[:signed_out] })
        end

        # The connection clamps a negative `first`, but only after this runs.
        raise ::Gitlab::Graphql::Errors::ArgumentError, '`first` must be a positive integer.' if first && first < 1

        if assignee_ids.present?
          if resource_ids.present?
            raise ::Gitlab::Graphql::Errors::ArgumentError, '`assigneeIds` cannot be combined with `resourceIds`.'
          end

          return resolve_by_assignees(assignee_ids, roles, first: first, after: after)
        end

        result = ::ArtifactRegistry::LookupRoleAssignmentsService.new(
          current_user: current_user,
          organization: context[:current_organization],
          resource_ids: resource_ids,
          roles: roles,
          page_size: [first, MAX_PAGE_SIZE].compact.min,
          page_after: after
        ).execute

        raise_lookup_error!(result) unless result.success?

        ::Gitlab::Graphql::ExternallyPaginatedArray.new(
          after,
          result.payload[:next_page_token],
          *result.payload[:role_assignments]
        )
      end

      private

      def raise_lookup_error!(result)
        raise_resource_not_available_error!(result.message, { code: ERROR_CODES.fetch(result.reason, 'unknown') })
      end

      # The service returns every matching assignment, so the cursor here is
      # an offset into that list rather than an IAM page token.
      def resolve_by_assignees(assignee_ids, roles, first:, after:)
        # Decoded first, so a bad cursor fails before the IAM lookup.
        offset = decode_offset(after)

        result = ::ArtifactRegistry::LookupAssigneeRoleAssignmentsService.new(
          current_user: current_user,
          organization: context[:current_organization],
          assignee_ids: assignee_ids,
          roles: roles
        ).execute

        raise_lookup_error!(result) unless result.success?

        role_assignments = result.payload[:role_assignments]
        # Clamped, because `drop` raises RangeError for an offset past a native integer.
        offset = [offset, role_assignments.size].min
        page = role_assignments.drop(offset).first([first, MAX_PAGE_SIZE].compact.min)
        next_offset = offset + page.size
        next_cursor = encode_offset(next_offset) if next_offset < role_assignments.size

        ::Gitlab::Graphql::ExternallyPaginatedArray.new(after, next_cursor, *page)
      end

      def encode_offset(offset)
        Base64.urlsafe_encode64(offset.to_s)
      end

      def decode_offset(cursor)
        return 0 if cursor.blank?

        offset = Integer(Base64.urlsafe_decode64(cursor), exception: false)
        raise ::Gitlab::Graphql::Errors::ArgumentError, 'Invalid cursor.' if offset.nil? || offset < 0

        offset
      rescue ArgumentError
        raise ::Gitlab::Graphql::Errors::ArgumentError, 'Invalid cursor.'
      end
    end
  end
end
