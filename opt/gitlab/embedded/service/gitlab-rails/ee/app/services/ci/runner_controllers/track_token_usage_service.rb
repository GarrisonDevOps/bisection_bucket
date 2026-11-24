# frozen_string_literal: true

module Ci
  module RunnerControllers
    class TrackTokenUsageService
      UPDATE_USED_COLUMN_EVERY = ((40.minutes)..(55.minutes))

      def initialize(token)
        @token = token
      end

      def execute
        track_values = { last_used_at: Time.current.utc }

        token.cache_attributes(track_values)

        token.update_columns(track_values) if can_update_track_values?

        ServiceResponse.success
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, runner_controller_id: token.runner_controller_id)

        ServiceResponse.error(message: e.message)
      end

      private

      attr_reader :token

      def can_update_track_values?
        last_used_at_max_age = Random.rand(UPDATE_USED_COLUMN_EVERY)

        real_last_used_at = token.read_attribute(:last_used_at)

        real_last_used_at.nil? ||
          (Time.current - real_last_used_at) >= last_used_at_max_age
      end
    end
  end
end
