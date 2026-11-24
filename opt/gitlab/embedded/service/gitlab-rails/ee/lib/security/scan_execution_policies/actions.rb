# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class Actions
      include Enumerable

      def initialize(actions)
        @actions = (actions || []).map { |action| Security::ScanExecutionPolicies::Action.new(action) }
      end

      attr_reader :actions

      delegate :each, :[], :map, to: :actions
    end
  end
end
