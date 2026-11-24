# frozen_string_literal: true

module WorkItems
  module Widgets
    class EscalationPolicy < Base
      def escalation_policy
        work_item.escalation_status&.policy
      end
    end
  end
end
