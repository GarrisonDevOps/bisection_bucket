# frozen_string_literal: true

module EE
  module API
    module ResourceLabelEvents
      extend ActiveSupport::Concern

      prepended do
        helpers do
          extend ::Gitlab::Utils::Override

          override :present_resource_label_event_collection
          def present_resource_label_event_collection(eventable, events, eventable_class)
            # This code uses helpers from NotesHelpers
            # eventable is not exactly a noteable, but they are the same object (epic in this case)
            if noteable_is_epic?(eventable_class)
              epic = extract_noteable_epic(eventable)
              present ::ResourceLabelEvent.visible_to_user?(current_user, paginate(events)),
                with: ::API::Entities::LegacyEpicResourceLabelEvent,
                epic: epic
            else
              super
            end
          end

          override :present_single_resource_label_event
          def present_single_resource_label_event(eventable, event, eventable_class)
            if noteable_is_epic?(eventable_class)
              epic = extract_noteable_epic(eventable)
              present event, with: ::API::Entities::LegacyEpicResourceLabelEvent, epic: epic
            else
              super
            end
          end
        end
      end
    end
  end
end
