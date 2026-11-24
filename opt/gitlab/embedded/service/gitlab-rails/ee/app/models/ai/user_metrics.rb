# frozen_string_literal: true

module Ai
  class UserMetrics < ApplicationRecord
    include Analytics::HasWriteBuffer

    self.table_name = 'ai_user_metrics'

    self.write_buffer_options = { class: Analytics::AiUserMetricsDatabaseWriteBuffer }

    belongs_to :user, optional: false

    validates :last_duo_activity_on, presence: true

    scope :for_users, ->(users) { where(user: users) }

    def self.refresh_last_activity_on(user, last_duo_activity_on: Time.current)
      write_buffer.add({ user_id: user.id, last_duo_activity_on: last_duo_activity_on })
    end
  end
end
