# frozen_string_literal: true

module Mutations
  module EpicTree
    class Reorder < ::Mutations::BaseMutation
      graphql_name "EpicTreeReorder"

      RATE_LIMIT_KEY = ::Mutations::WorkItems::Hierarchy::Reorder::RATE_LIMIT_KEY

      authorize :admin_epic_relation
      authorize_granular_token permissions: :update_epic, boundary_argument: :base_epic_id,
        boundary: :group, boundary_type: :group

      argument :base_epic_id,
        ::Types::GlobalIDType[::Epic],
        required: true,
        description: 'ID of the base epic of the tree.'

      argument :moved,
        Types::EpicTree::EpicTreeNodeInputType,
        required: true,
        description: 'Parameters for updating the tree positions.'

      def resolve(args)
        check_rate_limit!

        moving_object_id = args[:moved][:id]
        moving_params = args[:moved].to_hash.slice(:adjacent_reference_id, :relative_position, :new_parent_id).merge(base_epic_id: args[:base_epic_id])

        result = ::Epics::TreeReorderService.new(current_user, moving_object_id, moving_params).execute
        errors = result[:status] == :error ? [result[:message]] : []

        { errors: errors }
      end

      private

      def check_rate_limit!
        return unless ::Feature.enabled?(:work_item_hierarchy_reorder_rate_limit, current_user)
        return unless ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: { user: current_user })

        raise ::RateLimitedService::RateLimitedError.new(
          key: RATE_LIMIT_KEY, rate_limiter: ::Gitlab::ApplicationRateLimiter
        ), ::Gitlab::ApplicationRateLimiter.throttled_error_message
      end
    end
  end
end
