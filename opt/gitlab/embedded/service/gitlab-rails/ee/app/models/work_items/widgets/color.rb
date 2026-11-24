# frozen_string_literal: true

module WorkItems
  module Widgets
    class Color < Base
      delegate :color, :text_color, to: :color_instance, allow_nil: true

      def self.sync_params
        [:color]
      end

      def color_instance
        work_item&.color || WorkItems::Color.new
      end
    end
  end
end
