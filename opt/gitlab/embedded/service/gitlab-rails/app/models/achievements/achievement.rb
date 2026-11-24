# frozen_string_literal: true

module Achievements
  class Achievement < ApplicationRecord
    include Avatarable
    include StripAttribute

    belongs_to :namespace, inverse_of: :achievements, optional: false

    has_many :user_achievements, inverse_of: :achievement
    has_many :users, through: :user_achievements, inverse_of: :achievements

    strip_attributes! :name, :description

    # Lowest award priority first, then earliest award. Matches the profile order unless an
    # achievement's awards have mixed priorities.
    scope :with_user_achievement_counts, ->(user_achievements) {
      counts = user_achievements.reorder(nil).group(:achievement_id).select(
        :achievement_id,
        'COUNT(*) AS user_achievement_count',
        'MIN(user_achievements.created_at) AS first_awarded_at',
        'MAX(user_achievements.id) AS latest_user_achievement_id',
        'MIN(user_achievements.priority) AS min_priority',
        'MIN(user_achievements.id) AS first_user_achievement_id'
      )

      joins("INNER JOIN (#{counts.to_sql}) user_achievement_counts " \
        "ON user_achievement_counts.achievement_id = achievements.id")
        .select(
          arel_table[Arel.star],
          'user_achievement_counts.user_achievement_count',
          'user_achievement_counts.first_awarded_at',
          'user_achievement_counts.latest_user_achievement_id'
        )
        .order(Arel.sql('user_achievement_counts.min_priority ASC NULLS LAST'))
        .order(Arel.sql('user_achievement_counts.first_user_achievement_id ASC'))
    }

    validates :name,
      presence: true,
      length: { maximum: 255 },
      uniqueness: { case_sensitive: false, scope: [:namespace_id] },
      html_safety: true
    validates :description, length: { maximum: 1024 }, html_safety: true

    def unique_users
      users.distinct
    end

    def uploads_sharding_key
      { namespace_id: namespace_id }
    end
  end
end
