# frozen_string_literal: true

module Resolvers
  # rubocop:disable Gitlab/BoundedContexts -- the Achievements module already exists and holds the other resolvers as well
  module Achievements
    class UserAchievementCountsResolver < BaseResolver
      include LooksAhead

      type ::Types::Achievements::UserAchievementCountType.connection_type, null: true

      def resolve_with_lookahead
        # Counts are aggregated, so the per-award profile check on UserAchievement never runs
        unless Ability.allowed?(current_user, :read_user_profile, object)
          return offset_pagination(::Achievements::Achievement.none)
        end

        user_achievements = object.user_achievements.not_revoked.shown_on_profile

        # Grouped results can't be keyset paginated
        offset_pagination(
          apply_lookahead(::Achievements::Achievement.with_user_achievement_counts(user_achievements))
        )
      end

      private

      def unconditional_includes
        [:namespace]
      end
    end
  end
  # rubocop:enable Gitlab/BoundedContexts
end
