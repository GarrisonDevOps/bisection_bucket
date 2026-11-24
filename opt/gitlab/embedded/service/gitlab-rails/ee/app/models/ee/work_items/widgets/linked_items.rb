# frozen_string_literal: true

module EE
  module WorkItems
    module Widgets
      module LinkedItems
        extend ActiveSupport::Concern

        class_methods do
          extend ::Gitlab::Utils::Override

          override :quick_action_commands
          def quick_action_commands
            super + %i[blocks blocked_by]
          end

          def sorting_keys
            {
              blocking_issues_asc: {
                description: 'Blocking items count by ascending order.'
              },
              blocking_issues_desc: {
                description: 'Blocking items count by descending order.'
              }
            }
          end
        end
      end
    end
  end
end
