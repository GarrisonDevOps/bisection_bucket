# frozen_string_literal: true

module API
  class ResourceIterationEvents < ::API::Base
    include PaginationParams

    helpers ::API::Helpers::NotesHelpers

    resource_iteration_events_tags = %w[resource_events]
    before do
      authenticate!
    end

    { Issue => :team_planning }.each do |eventable_type, feature_category|
      parent_type = eventable_type.parent_class.to_s.underscore
      eventable_str = eventable_type.to_s.underscore
      eventables_str = eventable_str.pluralize
      eventable_article = eventable_str.match?(/\A[aeiou]/i) ? 'an' : 'a'

      params do
        requires :id, types: [String, Integer], desc: "ID or URL-encoded path of the #{parent_type}."
      end
      resource parent_type.pluralize.to_sym, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
        desc "List all #{eventable_str} iteration events" do
          detail "Lists all iteration events for a specified #{eventable_str}."
          success ::API::Entities::ResourceIterationEvent
          is_array true
          tags resource_iteration_events_tags
        end
        params do
          requires :eventable_id, types: [Integer, String], desc: 'ID of the eventable.'
          use :pagination
        end

        route_setting :tier, :premium
        route_setting :authorization, permissions: :"read_#{eventable_str}_iteration_event", boundary_type: :project
        get ":id/#{eventables_str}/:eventable_id/resource_iteration_events", feature_category: feature_category do
          eventable = find_noteable(eventable_type, params[:eventable_id])
          events = ::Issuables::ResourceIterationEventFinder.new(current_user, eventable).execute

          present paginate(events), with: ::API::Entities::ResourceIterationEvent
        end

        desc "Retrieve #{eventable_article} #{eventable_str} iteration event" do
          detail "Retrieves an iteration event for a specified #{eventable_str}."
          success ::API::Entities::ResourceIterationEvent
          tags resource_iteration_events_tags
        end
        params do
          requires :event_id, type: String, desc: 'ID of the resource iteration event.'
          requires :eventable_id, types: [Integer, String], desc: 'ID of the eventable.'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :"read_#{eventable_str}_iteration_event", boundary_type: :project
        get ":id/#{eventables_str}/:eventable_id/resource_iteration_events/:event_id", feature_category: feature_category do
          eventable = find_noteable(eventable_type, params[:eventable_id])
          event = eventable.resource_iteration_events.find(params[:event_id])

          not_found!('ResourceIterationEvent') unless can?(current_user, :read_iteration, event.iteration)

          present event, with: ::API::Entities::ResourceIterationEvent
        end
      end
    end
  end
end
