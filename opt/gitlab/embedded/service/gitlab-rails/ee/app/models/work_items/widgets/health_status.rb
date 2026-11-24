# frozen_string_literal: true

module WorkItems
  module Widgets
    class HealthStatus < Base
      include Gitlab::Utils::StrongMemoize

      delegate :health_status, to: :work_item

      class << self
        def quick_action_commands
          [:health_status, :clear_health_status]
        end

        def quick_action_params
          [:health_status]
        end

        def sorting_keys
          {
            health_status_asc: {
              description: 'Health status by ascending order.',
              experiment: { milestone: '17.11' }
            },
            health_status_desc: {
              description: 'Health status by descending order.',
              experiment: { milestone: '17.11' }
            }
          }
        end
      end

      def rolled_up_health_status
        WorkItem.health_statuses.map do |status, status_enum_value|
          { health_status: status, count: descendant_counts_by_health_status.fetch(status_enum_value, 0) }
        end
      end

      private

      def descendant_counts_by_health_status
        work_item.descendants
          .opened
          .with_any_health_status
          .counts_by_health_status
      end
      strong_memoize_attr :descendant_counts_by_health_status
    end
  end
end
