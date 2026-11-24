# frozen_string_literal: true

module WorkItems
  module TypesFramework
    module SystemDefined
      module Definitions
        module Objective
          class << self
            def widgets
              %w[
                ai_session
                assignees
                award_emoji
                current_user_todos
                custom_fields
                description
                health_status
                hierarchy
                labels
                linked_items
                milestone
                notes
                notifications
                participants
                progress
              ]
            end

            def widget_options
              {
                progress: { show_popover: true },
                hierarchy: { auto_expand_tree_on_move: true }
              }
            end

            def configuration
              {
                id: 6,
                name: 'Objective',
                base_type: 'objective',
                icon_name: "work-item-objective"
              }
            end

            def allowed_child_types
              [
                { type: :objective, maximum_depth: 9 },
                { type: :key_result, maximum_depth: 1 }
              ]
            end

            def license_name
              :okrs
            end

            def okr?
              true
            end
          end
        end
      end
    end
  end
end
