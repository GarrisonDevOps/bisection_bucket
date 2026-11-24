# frozen_string_literal: true

module Resolvers
  module WorkItems
    module Statuses
      class StatusResolver < Resolvers::WorkItems::BaseResolver
        type Types::WorkItems::StatusType, null: true

        def resolve
          return unless work_item_status_licensed_feature_available?

          work_item.status_with_fallback
        end

        private

        def root_ancestor
          work_item&.resource_parent&.root_ancestor
        end

        def work_item
          @work_item ||= object.is_a?(Issue) ? object : object.work_item
        end
      end
    end
  end
end
