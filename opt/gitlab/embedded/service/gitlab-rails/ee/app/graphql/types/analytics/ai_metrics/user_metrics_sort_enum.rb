# frozen_string_literal: true

module Types
  module Analytics
    module AiMetrics
      class UserMetricsSortEnum < BaseEnum
        graphql_name 'AiUserMetricsSort'
        description 'Values for sorting AI user metrics.'

        value "TOTAL_EVENTS_COUNT_DESC",
          description: "Total count of all AI events in descending order.",
          value: { field: :total_events_count, direction: :desc }

        value "TOTAL_EVENTS_COUNT_ASC",
          description: "Total count of all AI events in ascending order.",
          value: { field: :total_events_count, direction: :asc }

        # Feature-level sorting (total events across all events in a feature)
        Gitlab::Tracking::AiTracking.registered_features.each do |feature|
          value "#{feature}_TOTAL_COUNT_DESC".upcase,
            description: "#{feature.to_s.titleize} total event count in descending order.",
            value: { field: feature, direction: :desc }

          value "#{feature}_TOTAL_COUNT_ASC".upcase,
            description: "#{feature.to_s.titleize} total event count in ascending order.",
            value: { field: feature, direction: :asc }

          # Event-level sorting (individual events within features)
          Gitlab::Tracking::AiTracking.registered_user_action_events(feature).each_key do |event_name|
            value "#{event_name}_DESC".upcase,
              description: "#{event_name.to_s.titleize} event count in descending order.",
              value: { field: event_name, direction: :desc }

            value "#{event_name}_ASC".upcase,
              description: "#{event_name.to_s.titleize} event count in ascending order.",
              value: { field: event_name, direction: :asc }
          end
        end
      end
    end
  end
end
