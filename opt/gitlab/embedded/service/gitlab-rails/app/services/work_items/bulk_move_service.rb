# frozen_string_literal: true

module WorkItems
  class BulkMoveService
    def initialize(current_user:, work_item_ids:, source_namespace:, target_namespace:)
      @current_user = current_user
      @work_item_ids = work_item_ids
      @source_namespace = source_namespace
      @target_namespace = target_namespace
    end

    def execute
      error = validation_error
      return response(:error, message: error) if error

      check_rate_limit!

      moved_work_items =
        scoped_work_items
          .find_each(batch_size: 100) # rubocop:disable CodeReuse/ActiveRecord -- Implementation would be identical in model
          .filter_map do |work_item|
            next unless can_move_work_item?(work_item)

            begin
              move_result = ::WorkItems::DataSync::MoveService.new(
                work_item: work_item,
                current_user: @current_user,
                target_namespace: @target_namespace
              ).execute_without_rate_limiting

              work_item if move_result.success? && move_result[:work_item].present?
            rescue StandardError
              nil
            end
          end

      response(:success, moved_count: moved_work_items.count)
    end

    private

    def validation_error
      return "User namespaces are not supported as target namespaces." if @target_namespace&.user_namespace?

      # If the source namespace is a project and the target is a group, raise an error
      if @source_namespace&.project_namespace? && @target_namespace&.group_namespace?
        return "Cannot move work items from projects to groups."
      end

      unless Ability.allowed?(@current_user, :create_work_item, @target_namespace)
        return "You do not have permission to move items to this namespace."
      end

      limit = ::Gitlab::ApplicationRateLimiter.enforced_limit_for(:work_item_move, scope: { user: @current_user })
      return unless limit > 0 && @work_item_ids.size > limit

      format(
        n_('No more than %{limit} item can be moved at the same time',
          'No more than %{limit} items can be moved at the same time', limit),
        limit: limit
      )
    end

    # A batch is charged one unit per item before any move, so a throttled batch is rejected whole and the
    # moves above skip the per-item check.
    def check_rate_limit!
      return unless ::Gitlab::ApplicationRateLimiter.throttled?(
        :work_item_move, scope: { user: @current_user }, cost: @work_item_ids.size
      )

      raise ::RateLimitedService::RateLimitedError.new(
        key: :work_item_move, rate_limiter: ::Gitlab::ApplicationRateLimiter
      ), ::Gitlab::ApplicationRateLimiter.throttled_error_message
    end

    def response(status, message: nil, moved_count: 0)
      ServiceResponse.new(
        status: status,
        message: message,
        payload: { moved_work_item_count: moved_count }
      )
    end

    def can_move_work_item?(work_item)
      return false if work_item.namespace_id == @target_namespace.id
      return false unless Ability.allowed?(@current_user, :admin_work_item, work_item)
      return false unless work_item.supports_move_and_clone?

      true
    end

    def scoped_work_items
      WorkItem.find_on_namespaces(ids: @work_item_ids, resource_parent: @source_namespace)
    end
  end
end
