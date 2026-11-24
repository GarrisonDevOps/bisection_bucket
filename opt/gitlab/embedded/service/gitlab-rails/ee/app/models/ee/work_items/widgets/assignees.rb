# frozen_string_literal: true

module EE
  module WorkItems
    module Widgets
      module Assignees
        extend ActiveSupport::Concern

        class_methods do
          def allows_multiple_assignees?(resource_parent)
            resource_parent.licensed_feature_available?(:multiple_issue_assignees)
          end
        end
      end
    end
  end
end
