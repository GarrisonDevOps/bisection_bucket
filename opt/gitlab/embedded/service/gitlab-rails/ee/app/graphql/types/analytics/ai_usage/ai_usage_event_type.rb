# frozen_string_literal: true

module Types
  module Analytics
    module AiUsage
      # rubocop:disable Graphql/AuthorizeTypes -- authorized in parent type.
      class AiUsageEventType < BaseObject
        graphql_name 'AiUsageEvent'

        field :timestamp,
          Types::TimeType,
          null: false,
          description: 'When the event happened.'

        field :event,
          AiUsageEventTypeEnum,
          null: false,
          description: 'Type of the event.'

        field :user,
          Types::UserType,
          null: false,
          description: 'User associated with the event.'

        def event
          ::Ai::UsageEvent.events.key(object['event']) || object['event']
        end

        def user
          Gitlab::Graphql::Loaders::BatchModelLoader.new(User, object['user_id']).find
        end

        def extras
          value = object['extras']
          value.is_a?(String) ? ::Gitlab::Json::SafeParser.parse(value) : value
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
