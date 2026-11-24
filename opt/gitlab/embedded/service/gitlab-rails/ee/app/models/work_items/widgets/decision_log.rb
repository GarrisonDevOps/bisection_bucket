# frozen_string_literal: true

module WorkItems
  module Widgets
    class DecisionLog < Base
      # Same visibility gate as AgentPlan: hidden from users who can only read
      # the work item. Deliberate for v0; may be relaxed to read-level later.
      def self.required_user_ability
        :update_work_item
      end

      # Preloaded here rather than in a resolver so every GraphQL path
      # (list and single-item) loads options in one query
      def decisions
        work_item.decisions.preload(:options)
      end
    end
  end
end
