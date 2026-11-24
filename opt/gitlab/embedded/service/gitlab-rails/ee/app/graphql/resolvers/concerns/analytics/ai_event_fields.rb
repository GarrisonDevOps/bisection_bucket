# frozen_string_literal: true

module Analytics
  module AiEventFields
    extend ActiveSupport::Concern

    # Ai usage events exposed on API.
    # Uses AiUsageEventTypeEnum as single source of truth.
    COUNT_FIELD_SUFFIX = '_event_count'

    class_methods do
      def exposed_events(feature = nil)
        ::Gitlab::Tracking::AiTracking.registered_user_action_events(feature).keys
      end

      def count_field_name(event_name)
        (event_name + ::Analytics::AiEventFields::COUNT_FIELD_SUFFIX).to_sym
      end

      def expose_event_fields_for(feature)
        exposed_events(feature).each do |event_name|
          field count_field_name(event_name), GraphQL::Types::Int,
            null: true,
            description: "Total count of `#{event_name}` event."
        end
      end
    end
  end
end
