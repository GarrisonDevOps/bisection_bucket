# frozen_string_literal: true

module EE
  module API
    module Helpers
      module ResourceEventsHelpers
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        class_methods do
          extend ::Gitlab::Utils::Override

          override :eventable_types
          def eventable_types
            super.merge!(
              ::Epic => { feature_category: :portfolio_management, id_field: 'ID', tier: :premium }
            )
          end
        end

        override :present_resource_state_event_collection
        def present_resource_state_event_collection(events, eventable, eventable_type)
          if noteable_is_epic?(eventable_type)
            present_epic_resource_state_events(events, eventable)
          else
            super
          end
        end

        override :present_single_resource_state_event
        def present_single_resource_state_event(event, eventable, eventable_type)
          if noteable_is_epic?(eventable_type)
            present_epic_resource_state_event(event, eventable)
          else
            super
          end
        end

        private

        def present_epic_resource_state_events(events, eventable)
          epic = extract_noteable_epic(eventable)
          present events, with: ::API::Entities::LegacyEpicResourceStateEvent, epic: epic
        end

        def present_epic_resource_state_event(event, eventable)
          epic = extract_noteable_epic(eventable)
          present event, with: ::API::Entities::LegacyEpicResourceStateEvent, epic: epic
        end
      end
    end
  end
end
