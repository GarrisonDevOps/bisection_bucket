# frozen_string_literal: true

module WorkItems
  module TypesFramework
    module SystemDefined
      module Definitions
        module Epic
          class << self
            def widgets
              %w[
                ai_session
                assignees
                award_emoji
                color
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
                start_and_due_date
                status
                verification_status
                time_tracking
                weight
              ]
            end

            def widget_options
              {
                hierarchy: { propagates_milestone: true, auto_expand_tree_on_move: true },
                start_and_due_date: { can_roll_up: true }
              }
            end

            def configuration
              {
                id: 8,
                name: 'Epic',
                base_type: 'epic',
                icon_name: "work-item-epic"
              }
            end

            def allowed_child_types
              [
                { type: :epic, maximum_depth: 7 },
                { type: :issue, maximum_depth: 1 },
                { type: :ticket, maximum_depth: 1 }
              ]
            end

            def license_name
              :epics
            end

            # This method adds a configuration for the parent of the Type, and it coresponding license.
            # It should be a Hash with the format of: { parent.base_type.to_s: license_name.to_sym }
            def licenses_for_parent
              { 'epic' => :subepics }
            end

            # This method adds a configuration for the children of the Type, and its corresponding license.
            # It should be a Hash with the format of: { child.base_type.to_s: license_name.to_sym }
            def licenses_for_child
              { 'epic' => :subepics, 'issue' => :epics, 'ticket' => :epics }
            end

            def supports_roadmap_view?
              true
            end

            def configurable?
              false
            end

            def only_for_group?
              true
            end

            def supports_conversion?
              false
            end
          end
        end
      end
    end
  end
end
