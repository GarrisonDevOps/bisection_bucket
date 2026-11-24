# frozen_string_literal: true

module Resolvers
  module WorkItems
    module Widgets
      class AllowedStatusesResolver < Resolvers::WorkItems::BaseResolver
        include StatusLifecycle

        type [::Types::WorkItems::Widgets::StatusType], null: true

        alias_method :widget_definition, :object

        def resolve
          return [] unless work_item_status_licensed_feature_available?

          status_lifecycle&.ordered_statuses || []
        end
      end
    end
  end
end
