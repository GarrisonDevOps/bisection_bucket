# frozen_string_literal: true

module Resolvers
  module Govern
    class PoliciesResolver < BaseResolver
      UnmappedReasonError = Class.new(StandardError)

      UNMAPPED_REASON_MESSAGE = 'Could not complete the policy store request'
      IDS_WITH_PAGINATION_MESSAGE = 'ids cannot be combined with first or after'
      INVALID_CURSOR_MESSAGE = 'Invalid pagination cursor'
      MAX_OFFSET = ::Security::SecurityOrchestrationPolicies::PolicyStore::ListService::MAX_OFFSET

      authorize_granular_token permissions: :read_govern_policy,
        boundaries: [
          { boundary: :itself, boundary_type: :group },
          { boundary: :itself, boundary_type: :project },
          { boundary: :instance, boundary_type: :instance }
        ]

      type ::Types::Govern::PolicyType.connection_type, null: true

      argument :trigger_type, GraphQL::Types::String,
        required: false,
        experiment: { milestone: '19.4' },
        description: 'Return only the policies that respond to this trigger. ' \
          'Valid values are the ids in the policy store triggers catalog.'

      # Int, not GlobalID: GovernPolicy.id is a plain integer owned by the policy
      # store, mirroring the REST policy_id parameter.
      argument :ids, [GraphQL::Types::Int],
        required: false,
        validates: { length: { maximum: Types::BaseArgument::MAX_ARRAY_SIZE } },
        experiment: { milestone: '19.4' },
        description: 'Return only the policies with these IDs. Unknown IDs are ignored; ' \
          'an empty list returns no policies. ' \
          "Maximum is #{Types::BaseArgument::MAX_ARRAY_SIZE} IDs."

      # Runs once per container node; needs a batch API on the store before a
      # persistent (non in-memory) repository lands, or lists across containers N+1.
      def resolve(trigger_type: nil, ids: nil, first: nil, after: nil)
        return unless supported_container?

        # GovernPolicy.inherited is relative to the container being listed.
        context.scoped_set!(:policy_store_container, object)

        # The port returns every id match in one go, so a `first` below the match
        # count would drop policies while still reporting no next page.
        raise Gitlab::Graphql::Errors::ArgumentError, IDS_WITH_PAGINATION_MESSAGE if ids && (first || after)

        offset = decode_cursor(after)
        per_page = page_size(first)

        # ListService clamps per_page up to 1, which would turn `first: 0` into one row.
        return empty_page unless per_page > 0

        response = ::Security::SecurityOrchestrationPolicies::PolicyStore::ListService
          .new(
            container: object, current_user: current_user, trigger_type: trigger_type, ids: ids,
            offset: offset, per_page: per_page
          )
          .execute

        if response.error?
          return if [:experiment_not_active, :forbidden].include?(response.reason)

          raise GraphQL::ExecutionError, response.message if response.reason == :invalid

          # Mirror REST: track the unmapped reason and surface a generic error rather
          # than collapsing service failures into the same null the gates produce.
          ::Gitlab::ErrorTracking.track_exception(
            UnmappedReasonError.new("Unmapped policy store reason: #{response.reason}"),
            service_message: response.message
          )

          raise GraphQL::ExecutionError, UNMAPPED_REASON_MESSAGE
        end

        externally_paginated_array(response.payload)
      end

      private

      # The cursor is the offset of the next row, so `first` may change between requests.
      # It is derived from the window the service actually served, since the service owns
      # the clamping; past MAX_OFFSET no cursor is advertised for rows it cannot reach.
      def externally_paginated_array(payload)
        next_offset = payload[:offset] + payload[:per_page]
        has_next_page = payload[:has_next_page] && next_offset <= MAX_OFFSET
        end_cursor = encode_cursor(next_offset) if has_next_page

        Gitlab::Graphql::ExternallyPaginatedArray.new(
          nil, end_cursor, *payload[:policies], has_next_page: has_next_page
        )
      end

      def empty_page
        Gitlab::Graphql::ExternallyPaginatedArray.new(nil, nil, has_next_page: false)
      end

      def page_size(first)
        [first, field.max_page_size || context.schema.default_max_page_size].compact.min # rubocop:disable Graphql/Descriptions -- false positive on `field`
      end

      def encode_cursor(offset)
        Base64.strict_encode64(offset.to_s)
      end

      def decode_cursor(cursor)
        return 0 if cursor.blank?

        offset = decode_base64(cursor)
        raise Gitlab::Graphql::Errors::ArgumentError, INVALID_CURSOR_MESSAGE unless offset.match?(/\A\d+\z/)

        offset.to_i
      end

      def decode_base64(cursor)
        Base64.strict_decode64(cursor)
      rescue ArgumentError
        raise Gitlab::Graphql::Errors::ArgumentError, INVALID_CURSOR_MESSAGE
      end

      def supported_container?
        object.is_a?(::Organizations::Organization) || object.is_a?(::Group) || object.is_a?(::Project)
      end
    end
  end
end
