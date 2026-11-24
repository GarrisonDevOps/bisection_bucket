# frozen_string_literal: true

module WorkItems
  module TypesFramework
    module SystemDefined
      module Definitions
        module Requirement
          class << self
            def widgets
              %w[
                ai_session
                award_emoji
                current_user_todos
                description
                linked_items
                notes
                notifications
                participants
                requirement_legacy
                verification_status
                test_reports
                time_tracking
              ]
            end

            def widget_options
              {}
            end

            def configuration
              {
                id: 4,
                name: 'Requirement',
                base_type: 'requirement',
                icon_name: "work-item-requirement"
              }
            end

            def license_name
              :requirements
            end

            def creatable?
              false
            end

            def can_be_conversion_target?
              false
            end

            def filterable_list_view?
              false
            end

            def disabled_workflow_type?
              true
            end

            def configurable?
              false
            end
          end
        end
      end
    end
  end
end
