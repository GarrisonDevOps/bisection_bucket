# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class Actions
      def initialize(actions)
        @actions = (actions || []).map { |action| Security::ScanResultPolicies::Action.new(action) }
      end

      def require_approval_actions
        actions.select(&:type_require_approval?)
      end

      def send_bot_message_actions
        actions.select(&:type_send_bot_message?)
      end

      private

      attr_reader :actions
    end
  end
end
