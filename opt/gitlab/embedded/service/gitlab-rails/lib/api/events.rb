# frozen_string_literal: true

module API
  class Events < ::API::Base
    include PaginationParams
    include APIGuard
    include ::API::Concerns::McpAccess

    helpers ::API::Helpers::EventsHelpers

    allow_access_with_scope :read_user, if: ->(request) { request.get? || request.head? }
    allow_access_with_scope :ai_workflows, if: ->(request) { request_current_user_events?(request) }
    allow_mcp_access_read

    feature_category :user_profile
    urgency :low

    def self.request_current_user_events?(request)
      (request.get? || request.head?) && request.path.match?(%r{/api/v\d+/events$})
    end

    resource :events do
      desc 'List all events' do
        detail 'Lists all events for the authenticated user. Does not return events associated with epics or merge ' \
          'requests. Returns bulk push events with limited commit details. Events about a wiki page include a ' \
          '`wiki_page` object. To return only those events, set `target_type` to `wiki`. ' \
          'Requires a token with the `read_user` or `api` scope.'
        success Entities::Event
        is_array true
        tags %w[events]
        failure [
          { code: 401, message: 'Unauthorized' }
        ]
      end
      params do
        optional :scope, type: String,
          desc: "Include all events across the user's projects.",
          documentation: { example: 'all' }
        use :pagination
        use :event_filter_params
        use :sort_params
      end

      route_setting :authorization, permissions: :read_event, boundary_type: :user
      get do
        authenticate!

        events = find_events(current_user)

        present_events(events)
      end
    end

    params do
      requires :id, type: String, desc: 'ID or username of the user.'
    end
    resource :users do
      desc 'Retrieve contribution events for a user' do
        detail 'Retrieves the contribution events for a specified user. Does not return events associated with epics ' \
          'or merge requests. Returns bulk push events with limited commit details. ' \
          'A token used to authenticate must have the `read_user` or `api` scope.'
        success Entities::Event
        tags %w[events]
        is_array true
        failure [
          { code: 404, message: 'Not found' }
        ]
      end
      params do
        use :pagination
        use :event_filter_params
        use :sort_params
      end

      route_setting :mcp, tool_name: :list_user_events, toolset: :core,
        params: [:id, :action, :target_type, :before, :after, :sort, :page, :per_page],
        annotations: { title: 'List user events', readOnlyHint: true, idempotentHint: true, openWorldHint: false },
        ungovernable: true
      route_setting :authorization, permissions: :read_event, boundary_type: :user
      get ':id/events' do
        user = find_user(params[:id])
        not_found!('User') unless user

        events = find_events(user)

        present_events(events)
      end
    end
  end
end
