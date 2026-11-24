# frozen_string_literal: true

module Types
  # rubocop:disable Gitlab/BoundedContexts -- the Achievements module already exists and holds the other types as well
  module Achievements
    class UserAchievementCountType < BaseObject
      graphql_name 'UserAchievementCount'

      authorize :read_achievement

      authorize_granular_token permissions: :read_achievement,
        boundary: :user,
        boundary_type: :user

      field :achievement,
        ::Types::Achievements::AchievementType,
        null: false,
        method: :itself,
        description: 'Achievement awarded.'

      field :count,
        GraphQL::Types::Int,
        null: false,
        method: :user_achievement_count,
        description: 'Number of times the achievement was awarded to the user.'

      field :first_awarded_at,
        Types::TimeType,
        null: false,
        description: 'Timestamp the achievement was first awarded to the user.'

      field :latest_user_achievement,
        ::Types::Achievements::UserAchievementType,
        null: true,
        description: 'Most recent award of the achievement to the user.'

      def latest_user_achievement
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(
          ::Achievements::UserAchievement,
          object.latest_user_achievement_id,
          [:user, { achievement: :namespace }]
        ).find
      end
    end
  end
  # rubocop:enable Gitlab/BoundedContexts
end
