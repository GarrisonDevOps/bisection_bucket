# frozen_string_literal: true

module GovernUsageTracking
  include ProductAnalyticsTracking
  extend ActiveSupport::Concern

  included do
    def self.track_govern_activity(page_name, *controller_actions, conditions: nil)
      track_internal_event(*controller_actions,
        name: 'user_perform_visit',
        conditions: conditions,
        additional_properties: ->(controller) {
          {
            page_name: page_name
          }.merge(controller.additional_properties_for_tracking)
        }
      )
    end

    def additional_properties_for_tracking
      {}
    end
  end
end
