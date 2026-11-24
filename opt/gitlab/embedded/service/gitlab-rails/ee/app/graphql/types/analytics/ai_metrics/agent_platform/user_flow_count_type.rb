# frozen_string_literal: true

module Types
  module Analytics
    module AiMetrics
      module AgentPlatform
        # rubocop: disable Graphql/AuthorizeTypes -- authorized by parent type
        class UserFlowCountType < BaseObject
          graphql_name 'AgentPlatformUserFlowCount'
          description 'Agent platform flow counts aggergated per user'

          field :user,
            Types::UserType,
            null: true,
            description: 'User who triggered the flow.'

          field :flow_type,
            GraphQL::Types::String,
            null: false,
            description: 'Type of the flow.'

          field :sessions_count,
            GraphQL::Types::Int,
            null: false,
            description: 'Total number of flow sessions.'

          def user
            BatchLoader::GraphQL.for(object['user_id']).batch do |user_ids, loader|
              users = User.by_ids(user_ids).index_by(&:id)
              # User could be deleted, but the record still exists on ClickHouse.
              # In these cases fill with ghost user.
              user_ids.each do |user_id|
                user = users[user_id] || User.ghost.first
                loader.call(user_id, user)
              end
            end
          end
        end
        # rubocop: enable Graphql/AuthorizeTypes
      end
    end
  end
end
