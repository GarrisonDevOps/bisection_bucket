# frozen_string_literal: true

module MergeRequests
  module ReviewerAssignment
    class BaseStrategy
      def self.strategy_name
        raise NotImplementedError, "#{self} must implement .strategy_name"
      end

      def initialize(merge_request)
        @merge_request = merge_request
        @project = merge_request.project
      end

      def strategy_name
        self.class.strategy_name
      end

      def select_reviewers
        raise NotImplementedError, "#{self.class} must implement #select_reviewers"
      end

      private

      attr_reader :merge_request, :project
    end
  end
end
