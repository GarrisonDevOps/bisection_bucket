# frozen_string_literal: true

module WorkItems
  module TypesFramework
    module SystemDefined
      module Definitions
        module KeyResult
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
                notes
                notifications
                participants
                start_and_due_date
                progress
              ]
            end

            def widget_options
              {}
            end

            def configuration
              {
                id: 7,
                name: 'Key Result',
                base_type: 'key_result',
                icon_name: "work-item-keyresult"
              }
            end

            def license_name
              :okrs
            end

            def can_promote_to_objective?
              true
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
