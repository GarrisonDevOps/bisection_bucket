# frozen_string_literal: true

module ResourceEvents
  class ChangeWeightService
    attr_reader :resource, :user

    def initialize(resource, user)
      @resource = resource
      @user = user
    end

    def execute
      resource.resource_weight_events.create!(resource_weight_event_attributes)
      resource.broadcast_notes_changed

      if resource.is_a?(WorkItem)
        Gitlab::UsageDataCounters::WorkItemActivityUniqueCounter.track_work_item_weight_changed_action(author: user)
      else
        tracking_data = { author: user, project: resource.project }
        Gitlab::UsageDataCounters::IssueActivityUniqueCounter.track_issue_weight_changed_action(**tracking_data)
      end
    end

    private

    def resource_weight_event_attributes
      {
        user_id: user.id,
        issue_id: resource.id,
        weight: resource.weight,
        previous_weight: resource.previous_changes['weight']&.first,
        created_at: resource.system_note_timestamp
      }
    end
  end
end
