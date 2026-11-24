# frozen_string_literal: true

module Ci
  module TestBalancing
    class JobGroup < Ci::ApplicationRecord
      belongs_to :project

      validates :name, presence: true, length: { maximum: 255 }

      # Do not run inside a transaction: when create! fails due to
      # a concurrent insert, it would abort the outer transaction.
      # This is intentional to avoid subtransactions.
      def self.find_or_create!(project_id, name)
        attributes = { project_id: project_id, name: name }

        record = find_by(**attributes) || create!(**attributes)

        record.tap(&:touch_last_seen!)
      rescue ActiveRecord::RecordNotUnique, PG::UniqueViolation
        find_by!(**attributes).tap(&:touch_last_seen!)
      end

      def touch_last_seen!
        return if last_seen_at >= LAST_SEEN_THROTTLE_INTERVAL.ago

        self.class
          .where(id: id)
          .where(last_seen_at: ...LAST_SEEN_THROTTLE_INTERVAL.ago)
          .update_all(last_seen_at: Time.current)
      end
    end
  end
end
