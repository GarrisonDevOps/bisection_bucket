# frozen_string_literal: true

module MergeRequests
  module ReviewerAssignment
    class CodeOwnersStrategy < BaseStrategy
      def self.strategy_name
        'code_owners'
      end

      def select_reviewers
        merge_request.approval_state.wrapped_approval_rules
          .select(&:code_owner?)
          .flat_map(&:approvers)
          .reject(&:service_account?)
          .uniq
      end
    end
  end
end
