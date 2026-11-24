# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class UserType < BaseObject
        graphql_name 'GitlabSubscriptionUsageUser'
        description 'Describes the user with their usage data'

        authorize :read_user

        field :avatar_url,
          type: GraphQL::Types::String,
          null: true,
          description: "URL of the user's avatar."
        field :blocked_status,
          type: BlockedStatusType,
          null: true,
          description: 'Blocked status of the user under the subscription budget cap.'
        field :entity_type,
          type: GraphQL::Types::String,
          null: true,
          description: 'Type of consumer for the user usage.'
        field :events,
          type: EventType.connection_type,
          connection_extension: Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
          null: true,
          description: 'Usage events from the user. Billable events only, unless `includeNonBillable` is true.' do
            argument :flow_types, [GraphQL::Types::String, { null: true }],
              required: false,
              description: 'Filter events by one or more flow type IDs.'
            argument :include_non_billable, GraphQL::Types::Boolean,
              required: false,
              default_value: false,
              description: 'Also list events that were not billed. Each event then says whether it was billed ' \
                '(`billable`) and why not (`skipReason`); `eventType` is null.'
          end
        field :id,
          type: GlobalIDType[::User],
          null: false,
          description: 'Global ID of the user.'
        field :name,
          type: GraphQL::Types::String,
          null: false,
          resolver_method: :redacted_name,
          description: 'Human-readable name of the user.'
        field :usage,
          type: UserUsageType,
          null: true,
          description: 'Usage of consumables for a user under the subscription.'
        field :used_flow_types,
          type: [FlowTypeInfoType],
          null: true,
          description: 'Flow types used by the user during the billing period.' do
            argument :include_non_billable, GraphQL::Types::Boolean,
              required: false,
              default_value: false,
              description: 'Also include flow types the user only used without being billed.'
          end
        field :username,
          type: GraphQL::Types::String,
          null: false,
          description: 'Username of the user. Unique within the instance of GitLab.'

        BlockedStatus = Struct.new(
          :blocked,
          :cap_type,
          :declarative_policy_subject
        )

        UserEvent = Struct.new(
          :timestamp,
          :event_type,
          :flow_type,
          :project_id,
          :namespace_id,
          :credits_used,
          :session_id,
          :show_session_link,
          :billable,
          :skip_reason,
          :declarative_policy_subject
        )

        FlowTypeInfo = Struct.new(:id, :title, :declarative_policy_subject)

        def events(**args)
          return if object.is_a?(::GitlabSubscriptions::SubscriptionsUsage::UserWithConsumption)

          BatchLoader::GraphQL.for(object.id).batch(key: [:events, args]) do |user_ids, loader|
            load_users_events(user_ids, args, loader)
          end
        end

        def used_flow_types(include_non_billable: false)
          BatchLoader::GraphQL.for(object.id).batch(key: [:used_flow_types, include_non_billable]) do |user_ids, loader|
            load_used_flow_types(user_ids, loader, include_non_billable: include_non_billable)
          end
        end

        def usage
          if object.is_a?(::GitlabSubscriptions::SubscriptionsUsage::UserWithConsumption)
            object.usage
          else
            flow_types = context[:flow_types]
            BatchLoader::GraphQL.for(object.id).batch(key: flow_types) do |user_ids, loader|
              load_users_usage(user_ids, loader, flow_types: flow_types)
            end
          end
        end

        def entity_type
          object.entity_type if object.is_a?(::GitlabSubscriptions::SubscriptionsUsage::UserWithConsumption)
        end

        def blocked_status
          BatchLoader::GraphQL.for(object.id).batch(key: :blocked_statuses) do |user_ids, loader|
            load_blocked_statuses(user_ids, loader)
          end
        end

        private

        def load_users_usage(user_ids, loader, flow_types: nil)
          result = context[:subscription_usage_client].get_usage_for_user_ids(user_ids, flow_types: flow_types)

          return unless result[:usersUsage]

          result[:usersUsage].each do |usage|
            loader.call(
              usage[:userId],
              ::GitlabSubscriptions::SubscriptionsUsage::UserConsumptionStatistics.new(object, usage)
            )
          end
        end

        def load_blocked_statuses(user_ids, loader)
          entity_ids = user_ids.map(&:to_s)
          result = context[:subscription_usage_client].get_blocked_statuses(entity_ids)

          return unless result[:blockedStatuses]

          policy_subject = if object.is_a?(::GitlabSubscriptions::SubscriptionsUsage::UserWithConsumption)
                             object.declarative_policy_subject
                           else
                             object
                           end

          result[:blockedStatuses].each do |status|
            user_id = status[:entityId].to_i
            next unless user_ids.include?(user_id)

            loader.call(
              user_id,
              BlockedStatus.new(
                blocked: status[:blocked],
                cap_type: status[:capType],
                declarative_policy_subject: policy_subject
              )
            )
          end
        end

        def load_used_flow_types(user_ids, loader, include_non_billable: false)
          return unless user_ids.length == 1

          result = context[:subscription_usage_client]
            .get_used_flow_types_for_user_id(user_ids.first, include_non_billable: include_non_billable)

          return unless result[:usedFlowTypes]

          flow_types = result[:usedFlowTypes].map do |ft|
            FlowTypeInfo.new(ft[:id], ft[:title], object)
          end

          loader.call(user_ids.first, flow_types)
        end

        def load_users_events(user_ids, args, loader)
          # We only resolve events if only one user was resolved to avoid overaloading CustomersDot API
          return unless user_ids.length == 1

          result = context[:subscription_usage_client].get_events_for_user_id(user_ids.first, args)

          return unless result[:userEvents]

          user_events = result.dig(:userEvents, :nodes).to_a.map do |event|
            UserEvent.new(
              timestamp: event[:timestamp],
              event_type: event[:eventType],
              flow_type: event[:flowType],
              project_id: event[:projectId],
              namespace_id: event[:namespaceId],
              credits_used: event[:creditsUsed],
              session_id: event[:sessionId],
              show_session_link: event[:showSessionLink],
              billable: event[:billable],
              skip_reason: event[:skipReason],
              declarative_policy_subject: object
            )
          end

          loader.call(
            user_ids.first,
            Gitlab::Graphql::ExternallyPaginatedArray.new(
              result.dig(:userEvents, :pageInfo, :startCursor),
              result.dig(:userEvents, :pageInfo, :endCursor),
              *user_events,
              has_next_page: result.dig(:userEvents, :pageInfo, :hasNextPage),
              has_previous_page: result.dig(:userEvents, :pageInfo, :hasPreviousPage)
            )
          )
        end
      end
    end
  end
end
