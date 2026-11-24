# frozen_string_literal: true

module WorkItems
  module Widgets
    class Weight < Base
      include Gitlab::Utils::StrongMemoize

      class << self
        def quick_action_commands
          [:weight, :clear_weight]
        end

        def quick_action_params
          [:weight]
        end

        def sorting_keys
          {
            weight_asc: {
              description: 'Weight by ascending order.',
              experiment: { milestone: '17.11' }
            },
            weight_desc: {
              description: 'Weight by descending order.',
              experiment: { milestone: '17.11' }
            }
          }
        end
      end

      def weight
        work_item.weight
      end

      def rolled_up_weight
        work_item.weights_source&.rolled_up_weight
      end

      def rolled_up_completed_weight
        work_item.weights_source&.rolled_up_completed_weight
      end
    end
  end
end
