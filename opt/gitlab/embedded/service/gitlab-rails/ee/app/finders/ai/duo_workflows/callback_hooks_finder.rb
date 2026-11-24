# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Finds the webhooks a Duo flow may use as a callback endpoint.
    #
    # A hook qualifies when it has `duo_flow_callback_enabled` set and belongs to
    # the container the flow runs in, or to one of that container's ancestor
    # groups. Resolving ancestors mirrors how group webhooks already fan out to
    # descendant projects for every other event type.
    #
    # Authorization is containment: the caller is already authorized to run a flow
    # in the container, and only a hook owner can set `duo_flow_callback_enabled`.
    class CallbackHooksFinder
      def initialize(container:)
        @container = container
      end

      def execute
        # rubocop: disable CodeReuse/ActiveRecord -- duo_flow_callback_enabled has no scope of its own
        hooks.where(duo_flow_callback_enabled: true)
        # rubocop: enable CodeReuse/ActiveRecord
      end

      def find_by_id(id)
        execute.find_by_id(id)
      end

      private

      attr_reader :container

      def hooks
        case container
        when Project
          WebHook.from_union([container.hooks, ancestor_group_hooks], remove_duplicates: false)
        when Group
          ancestor_group_hooks
        else
          WebHook.none
        end
      end

      # Group webhooks are a licensed feature, so an unlicensed hierarchy resolves
      # to no group hooks here, just as it does for every other event type.
      def ancestor_group_hooks
        group = container.is_a?(Project) ? container.group : container
        return GroupHook.none unless group&.licensed_feature_available?(:group_webhooks)

        GroupHook.where(group_id: group.self_and_ancestors) # rubocop: disable CodeReuse/ActiveRecord -- mirrors EE::Project#group_hooks
      end
    end
  end
end
