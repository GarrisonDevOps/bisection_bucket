# frozen_string_literal: true

module API
  class ResourceWeightEvents < ::API::Base
    include PaginationParams

    helpers ::API::Helpers::NotesHelpers

    before do
      authenticate!
    end

    resource_weight_events_tags = %w[resource_events]
    feature_category :team_planning
    urgency :low

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'List all project issue weight events' do
        detail 'Lists all weight events for a specified issue.'
        success ::API::Entities::ResourceWeightEvent
        is_array true
        tags resource_weight_events_tags
      end
      params do
        requires :eventable_id, types: [Integer, String], desc: 'ID of the eventable.'
        use :pagination
      end

      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_issue_weight_event, boundary_type: :project
      get ":id/issues/:eventable_id/resource_weight_events" do
        eventable = find_noteable(Issue, params[:eventable_id])

        events = if Ability.allowed?(current_user, :read_issue, eventable)
                   eventable.resource_weight_events.with_api_entity_associations
                 else
                   ResourceWeightEvent.none
                 end

        present paginate(events), with: ::API::Entities::ResourceWeightEvent
      end

      desc 'Retrieve single issue weight event' do
        detail 'Retrieves a single weight event for a specified project issue.'
        success ::API::Entities::ResourceWeightEvent
        failure [
          { code: 404, message: 'Not found' }
        ]
        tags resource_weight_events_tags
      end
      params do
        requires :event_id, type: String, desc: 'ID of the resource weight event.'
        requires :eventable_id, types: [Integer, String], desc: 'ID of the eventable.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_issue_weight_event, boundary_type: :project
      get ":id/issues/:eventable_id/resource_weight_events/:event_id" do
        eventable = find_noteable(Issue, params[:eventable_id])

        event = eventable.resource_weight_events.find(params[:event_id])

        not_found!('ResourceWeightEvent') unless can?(current_user, :read_issue, event.issue)

        present event, with: ::API::Entities::ResourceWeightEvent
      end
    end
  end
end
