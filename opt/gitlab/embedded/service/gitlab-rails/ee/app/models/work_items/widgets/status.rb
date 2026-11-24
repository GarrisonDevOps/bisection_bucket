# frozen_string_literal: true

module WorkItems
  module Widgets
    class Status < Base
      class << self
        def quick_action_commands
          [:status]
        end

        def quick_action_params
          [:status]
        end

        def sorting_keys
          {
            status_asc: {
              description: 'Status by ascending order.',
              experiment: { milestone: '18.3' }
            },
            status_desc: {
              description: 'Status by descending order.',
              experiment: { milestone: '18.3' }
            }
          }
        end
      end
    end
  end
end
