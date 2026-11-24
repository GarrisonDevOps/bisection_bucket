# frozen_string_literal: true

module EE
  module Gitlab
    module EventStore
      module Subscriptions
        module WorkItemsSubscriptions
          def register
            super

            store.subscribe ::WorkItems::RolledupDates::UpdateRolledupDatesEventHandler,
              to: ::WorkItems::WorkItemCreatedEvent
            store.subscribe ::WorkItems::RolledupDates::UpdateRolledupDatesEventHandler,
              to: ::WorkItems::WorkItemDeletedEvent
            store.subscribe ::WorkItems::RolledupDates::UpdateRolledupDatesEventHandler,
              to: ::WorkItems::WorkItemUpdatedEvent,
              if: ->(event) {
                ::WorkItems::RolledupDates::UpdateRolledupDatesEventHandler.can_handle_update?(event)
              }

            store.subscribe ::WorkItems::RolledupDates::BulkUpdateHandler,
              to: ::WorkItems::BulkUpdatedEvent,
              if: ->(event) {
                ::WorkItems::RolledupDates::BulkUpdateHandler.can_handle?(event)
              }

            store.subscribe ::WorkItems::Weights::UpdateRolledUpWeightsEventHandler,
              to: ::WorkItems::WorkItemCreatedEvent,
              if: ->(event) {
                ::WorkItems::Weights::UpdateRolledUpWeightsEventHandler.can_handle?(event)
              }
            store.subscribe ::WorkItems::Weights::UpdateRolledUpWeightsEventHandler,
              to: ::WorkItems::WorkItemDeletedEvent,
              if: ->(event) {
                ::WorkItems::Weights::UpdateRolledUpWeightsEventHandler.can_handle?(event)
              }
            store.subscribe ::WorkItems::Weights::UpdateRolledUpWeightsEventHandler,
              to: ::WorkItems::WorkItemUpdatedEvent,
              if: ->(event) {
                ::WorkItems::Weights::UpdateRolledUpWeightsEventHandler.can_handle?(event)
              }
            store.subscribe ::WorkItems::Weights::UpdateRolledUpWeightsEventHandler,
              to: ::WorkItems::WorkItemClosedEvent,
              if: ->(event) {
                ::WorkItems::Weights::UpdateRolledUpWeightsEventHandler.can_handle?(event)
              }
            store.subscribe ::WorkItems::Weights::UpdateRolledUpWeightsEventHandler,
              to: ::WorkItems::WorkItemReopenedEvent,
              if: ->(event) {
                ::WorkItems::Weights::UpdateRolledUpWeightsEventHandler.can_handle?(event)
              }
            store.subscribe ::WorkItems::RolledupDates::UpdateMilestoneRelatedWorkItemDatesEventHandler,
              to: ::Milestones::MilestoneUpdatedEvent,
              if: ->(event) {
                ::WorkItems::RolledupDates::UpdateMilestoneRelatedWorkItemDatesEventHandler.can_handle?(event)
              }
          end
        end
      end
    end
  end
end
