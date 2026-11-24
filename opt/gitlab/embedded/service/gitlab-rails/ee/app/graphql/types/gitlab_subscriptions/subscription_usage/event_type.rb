# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class EventType < BaseObject
        graphql_name 'GitlabSubscriptionUsageUserEvent'
        description 'Describes a usage event for the subscription.'

        authorize :read_user

        field :timestamp, GraphQL::Types::ISO8601DateTime, null: true,
          description: 'Date and time of the event.'

        field :event_type, GraphQL::Types::String, null: true,
          deprecated: { reason: 'Use `flowType`', milestone: '19.6' },
          description: 'Event type. Null when `events` was queried with `includeNonBillable: true`.'

        field :flow_type, GraphQL::Types::String, null: true,
          description: 'User-friendly display name for the event flow type.'

        field :location, EventLocationType, null: true,
          description: 'Event location: project or namespace.'

        field :location_id, ::Types::GlobalIDType, null: true,
          description: 'Global ID of the event location. ' \
            'Populated even when the referenced record is deleted or not visible to the user, unlike `location`. ' \
            'When both fields are present, they identify the same record.'

        field :credits_used, GraphQL::Types::Float, null: true,
          description: 'GitLab Credits consumed on the date.'

        field :session_link, GraphQL::Types::String, null: true,
          description: 'URL of the agent session associated with the event.'

        field :billable, GraphQL::Types::Boolean, null: true,
          description: 'Whether the event was billed. Only populated when `events` was queried with ' \
            '`includeNonBillable: true`; null otherwise, and null when the Customer Portal does not report it.'

        field :skip_reason, GraphQL::Types::String, null: true,
          description: 'Reason the event was not billed, as recorded on the usage event. ' \
            'Null for billable events and for skipped events without a recorded reason.'

        def location
          if object.project_id
            Gitlab::Graphql::Loaders::BatchModelLoader.new(Project, object.project_id).find
          else
            Gitlab::Graphql::Loaders::BatchModelLoader.new(Group, object.namespace_id).find
          end
        end

        # Returns a URI::GID rather than a String: GlobalIDType#coerce_result raises on plain
        # strings because it cannot infer the model name from them.
        def location_id
          if object.project_id
            ::Gitlab::GlobalId.build(model_name: 'Project', id: object.project_id)
          elsif object.namespace_id
            ::Gitlab::GlobalId.build(model_name: 'Group', id: object.namespace_id)
          end
        end

        def session_link
          return unless object.show_session_link && object.project_id && object.session_id

          key = [object.project_id, object.session_id]
          BatchLoader::GraphQL.for(key).batch { |keys, loader| batch_load_session_links(keys, loader) }
        end

        private

        def batch_load_session_links(keys, loader)
          project_ids = keys.map(&:first).uniq
          projects_by_id = Project.id_in(project_ids).index_by(&:id)

          keys.each do |project_id, session_id|
            project = projects_by_id[project_id.to_i]
            next unless project

            url = "#{Gitlab::Routing.url_helpers.project_automate_agent_sessions_url(project)}/#{session_id}"
            loader.call([project_id, session_id], url)
          end
        end
      end
    end
  end
end
