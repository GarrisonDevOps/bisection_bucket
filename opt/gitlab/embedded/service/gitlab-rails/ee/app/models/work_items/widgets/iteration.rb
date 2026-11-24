# frozen_string_literal: true

module WorkItems
  module Widgets
    class Iteration < Base
      delegate :iteration, to: :work_item

      def self.quick_action_commands
        [:iteration, :remove_iteration]
      end

      def self.quick_action_params
        [:iteration]
      end
    end
  end
end
