# frozen_string_literal: true

module WorkItems
  module Callbacks
    class Hierarchy < Base
      INVALID_RELATIVE_POSITION_ERROR = 'Relative position is not valid.'
      CHILDREN_REORDERING_ERROR = 'Relative position cannot be combined with childrenIds.'
      UNRELATED_ADJACENT_HIERARCHY_ERROR = 'The adjacent work item\'s parent must match the new parent work item.'
      INVALID_ADJACENT_PARENT_ERROR = 'The adjacent work item\'s parent must match the current parent work item.'

      MAX_CHILDREN_PER_REQUEST = 50
      ADD_CHILDREN_RATE_LIMIT_KEY = :work_item_hierarchy_add_children

      def self.children_limit_exceeded?(children, user)
        too_many_children?(children) && Feature.enabled?(:work_item_hierarchy_add_children_limits, user)
      end

      # `childrenIds: null` is valid on `workItemUpdate`, so children can be nil.
      def self.too_many_children?(children)
        Array(children).size > MAX_CHILDREN_PER_REQUEST
      end

      def self.children_limit_error_message
        format(
          _('No more than %{limit} child items can be added at the same time.'),
          limit: MAX_CHILDREN_PER_REQUEST
        )
      end

      def after_create
        handle_service_response!(handle_hierarchy_changes)
      end

      def after_update
        if positioning?
          handle_service_response!(handle_positioning)
        else
          handle_service_response!(handle_hierarchy_changes)
        end
      end

      private

      def handle_service_response!(response)
        work_item.reload_work_item_parent
        work_item.work_item_children.reset

        raise_error response[:message] if response&.fetch(:status) == :error
      end

      def positioning?
        params[:relative_position].present? || params[:adjacent_work_item].present?
      end

      def handle_positioning
        validate_positioning_params!

        arguments = {
          target_issuable: work_item,
          adjacent_work_item: params[:adjacent_work_item],
          relative_position: params[:relative_position]
        }
        work_item_parent = params[:parent] || work_item.work_item_parent
        ::WorkItems::ParentLinks::ReorderService.new(work_item_parent, current_user, arguments).execute
      end

      def validate_positioning_params!
        raise_error(INVALID_RELATIVE_POSITION_ERROR) if incomplete_relative_position?
        raise_error(CHILDREN_REORDERING_ERROR) if missing_positioning_children?
        raise_error(UNRELATED_ADJACENT_HIERARCHY_ERROR) if unrelated_adjacent_hierarchy?
        raise_error(INVALID_ADJACENT_PARENT_ERROR) if invalid_adjacent_parent?
      end

      def handle_hierarchy_changes
        validate_hierarchy_change_params!

        if params.key?(:parent)
          update_work_item_parent(params[:parent])
        elsif params.key?(:children)
          update_work_item_children(params[:children])
        elsif params.key?(:remove_child)
          remove_parent_link(params[:remove_child])
        end
      end

      def validate_hierarchy_change_params!
        hierarchy_change_params = [:children, :parent, :remove_child]

        param_count = params.slice(*hierarchy_change_params).size

        if param_count > 1
          raise_error(format(
            _("One and only one of %{params} is required"),
            params: hierarchy_change_params.to_sentence(last_word_connector: ' or ')
          ))
        elsif param_count == 0
          raise_error(format(
            _("One or more arguments are invalid: %{args}."),
            args: params.keys.to_sentence
          ))
        end
      end

      def update_work_item_parent(parent)
        return remove_parent_link(work_item) if parent.nil?

        service_params = { target_issuable: work_item }.merge(
          params.slice(:relative_position)
        )

        service_response = ::WorkItems::ParentLinks::CreateService
          .new(parent, current_user, service_params)
          .execute

        # Reference the parent instead because the error is returned in the child context
        if service_response[:status] == :error
          service_response[:message].sub!(/#.* cannot be added/, "#{parent.to_reference} cannot be added")
        end

        service_response
      end

      def update_work_item_children(children)
        enforce_add_children_limits!(children)

        ::WorkItems::ParentLinks::CreateService
          .new(work_item, current_user, { issuable_references: children })
          .execute
      end

      # Each child costs ~50 queries and 7 rows inside the parent's save transaction, so the per-request
      # cap is the main protection and the per-user limit bounds the churn. Every add-children path shares
      # this point. The flag gates the cap here and, through the staged rule, enforcement of the rate limit.
      def enforce_add_children_limits!(children)
        return if params[:skip_add_children_limits]

        if self.class.children_limit_exceeded?(children, current_user)
          raise_error(self.class.children_limit_error_message)
        end

        return unless rate_limited?(children)

        raise ::RateLimitedService::RateLimitedError.new(
          key: ADD_CHILDREN_RATE_LIMIT_KEY, rate_limiter: ::Gitlab::ApplicationRateLimiter
        ), ::Gitlab::ApplicationRateLimiter.throttled_error_message
      end

      # Charges one unit per child, since the cost of a request grows with the number of children.
      def rate_limited?(children)
        ::Gitlab::ApplicationRateLimiter.throttled?(
          ADD_CHILDREN_RATE_LIMIT_KEY, scope: { user: current_user }, cost: Array(children).size
        )
      end

      def remove_parent_link(child)
        link = ::WorkItems::ParentLink.find_by_work_item_id(child)
        return unless link.present?

        ::WorkItems::ParentLinks::DestroyService.new(link, current_user).execute
      end

      def incomplete_relative_position?
        params[:adjacent_work_item].blank? || params[:relative_position].blank?
      end

      def missing_positioning_children?
        params.key?(:children)
      end

      def unrelated_adjacent_hierarchy?
        return false if params[:parent].blank?

        params[:parent] != params[:adjacent_work_item].work_item_parent
      end

      def invalid_adjacent_parent?
        return false if params[:parent].present?

        work_item.work_item_parent != params[:adjacent_work_item].work_item_parent
      end
    end
  end
end
