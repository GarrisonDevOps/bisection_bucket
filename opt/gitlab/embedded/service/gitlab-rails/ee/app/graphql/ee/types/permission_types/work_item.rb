# frozen_string_literal: true

module EE
  module Types
    module PermissionTypes
      module WorkItem # rubocop:disable Gitlab/BoundedContexts -- Types::WorkItem is CE class
        extend ActiveSupport::Concern

        prepended do
          field :blocked_work_items, GraphQL::Types::Boolean, null: true,
            description: 'If `true`, the user can perform `blocked_work_items` on the work item.'

          def blocked_work_items
            object.namespace&.feature_available?(:blocked_work_items)
          end
        end
      end
    end
  end
end
