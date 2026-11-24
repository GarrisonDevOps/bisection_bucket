# frozen_string_literal: true

module MergeRequests
  module ReviewerAssignment
    class StrategyFactory
      STRATEGIES = {
        'code_owners' => CodeOwnersStrategy
      }.freeze

      def self.build(merge_request)
        strategy_name = merge_request.project.project_setting.reviewer_assignment_strategy
        strategy_class = STRATEGIES[strategy_name]

        return unless strategy_class

        strategy_class.new(merge_request)
      end
    end
  end
end
