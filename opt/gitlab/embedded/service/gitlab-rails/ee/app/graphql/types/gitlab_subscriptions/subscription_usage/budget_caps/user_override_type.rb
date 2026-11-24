# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      module BudgetCaps
        class UserOverrideType < BaseObject
          graphql_name 'GitlabSubscriptionBudgetCapUserOverride'
          description 'Per-user budget cap override.'

          authorize :read_subscription_usage

          field :user, ::Types::UserType,
            null: true,
            description: 'GitLab user the override applies to.'

          field :cap, GraphQL::Types::Float,
            null: false,
            description: 'Budget cap amount for the user.'

          field :cap_enabled, GraphQL::Types::Boolean,
            null: false,
            description: 'Whether the budget cap is enabled for the user.'

          field :created_at, Types::TimeType,
            null: true,
            description: 'When the override was created.'

          field :updated_at, Types::TimeType,
            null: true,
            description: 'When the override was last updated.'

          def user
            return unless object.entity_id

            BatchLoader::GraphQL
              .for(object.entity_id.to_i)
              .batch do |user_ids, loader|
                ::User.id_in(user_ids).each do |u|
                  loader.call(u.id, u)
                end
              end
          end

          def created_at
            parse_time(object.created_at)
          end

          def updated_at
            parse_time(object.updated_at)
          end

          private

          def parse_time(value)
            return unless value

            Time.zone.parse(value)
          rescue ArgumentError
            nil
          end
        end
      end
    end
  end
end
