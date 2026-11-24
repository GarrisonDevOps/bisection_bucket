# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      # Decides whether a session is due for a transcript walk. The quieter a session has
      # been since its last message, the longer we wait between walks. Keyed on the last
      # message, not session age, so a long session that is still active keeps being read.
      #
      # The intervals are first guesses, not measured. At the 6-hour list schedule only the 1h and 3h
      # waits can skip a listing, after a walk that finished late; the 6h cap is unreachable inside
      # the 12-hour list window.
      class TranscriptTaper
        # [quiet for less than, wait at least this long since the last finished walk]
        BACKOFF = [
          [1.hour, 0.seconds],
          [6.hours, 1.hour],
          [12.hours, 3.hours]
        ].freeze
        MAX_BACKOFF = 6.hours
        # Under the 6-hour list schedule, so the next listing retries a failed walk that started within
        # an hour of its listing, if the session is still inside the 12-hour list window.
        STALE_WALK_AFTER = 5.hours

        # @param walk_state [Ai::Compliance::Anthropic::Session, nil] nil when no walk-state row exists yet
        # @param last_message_at [Time, String, nil] the session's latest activity, such as the
        #   session list's `updated_at`
        def self.due?(walk_state:, last_message_at:, now: Time.current)
          new(walk_state: walk_state, last_message_at: last_message_at, now: now).due?
        end

        def initialize(walk_state:, last_message_at:, now: Time.current)
          @walk_state = walk_state
          @last_message_at = parse_time(last_message_at)
          @now = now
        end

        def due?
          return true if walk_state.nil?
          # A walk in progress is left to finish; an abandoned one never commits, so the next walk
          # starts over from the stored watermark.
          return walk_state.walk_started_at <= now - STALE_WALK_AFTER if walk_state.walk_started_at.present?
          return true if never_finished_a_walk?
          return true if last_message_at.nil?

          last_finished_walk_at <= now - backoff
        end

        private

        attr_reader :walk_state, :last_message_at, :now

        # An empty or not-found walk leaves no watermark, but its commit still moves updated_at.
        def never_finished_a_walk?
          walk_state.message_watermark.blank? && walk_state.updated_at <= walk_state.created_at
        end

        # Only a commit touches a row whose walk is not in progress, so updated_at is when the
        # last walk finished.
        def last_finished_walk_at
          walk_state.updated_at
        end

        def backoff
          quiet_for = now - last_message_at
          tier = BACKOFF.find { |quiet_limit, _| quiet_for < quiet_limit }

          tier ? tier.last : MAX_BACKOFF
        end

        def parse_time(value)
          value.is_a?(String) ? Time.iso8601(value) : value
        rescue ArgumentError
          nil
        end
      end
    end
  end
end
