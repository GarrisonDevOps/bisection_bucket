# frozen_string_literal: true

module Gitlab
  module Graphql
    module Subscriptions
      # Runs the first update of a burst at once and keeps only the newest merged update for the end of the
      # window, so the last update always runs. It does no Redis, database or Sidekiq work.
      class Coalescer
        MAX_KEYS = 10_000
        MAX_KEYS_PER_TOPIC = 1_000

        Key = Data.define(:topic, :fingerprint, :record)

        Burst = Data.define(:length, :dispatch, :pending, :due) do
          def initialize(length:, dispatch:, pending: nil, due: nil)
            super
          end

          def absorb(update, dispatch)
            with(pending: pending ? yield(pending, update) : update, dispatch: dispatch, due: nil)
          end

          def pending?
            !pending.nil?
          end

          def drain
            with(pending: nil, due: pending)
          end

          def flush
            dispatch.call(due)
          end
        end

        # `merge` combines the pending update with a newer one.
        # `scheduler` runs a block after a delay.
        def initialize(merge:, scheduler: Concurrent::ScheduledTask.method(:execute))
          @merge = merge
          @scheduler = scheduler
          @bursts = Concurrent::Map.new
          @topics = Concurrent::Map.new
        end

        def size
          @bursts.size
        end

        # Returns :run when the caller runs `update` now, :overflow when it must run it now because a cap is
        # full, or :deferred when `dispatch` runs the merged update when the window ends.
        def submit(key, update, window:, &dispatch)
          burst = enter(key, update, window, dispatch)
          return :overflow unless burst

          burst.pending? ? :deferred : start(key, window)
        end

        private

        def enter(key, update, length, dispatch)
          @bursts.compute(key) do |open|
            open&.absorb(update, dispatch, &@merge) || admit(key.topic, length, dispatch)
          end
        end

        def admit(topic, length, dispatch)
          Burst.new(length:, dispatch:) unless full?(topic)
        end

        def full?(topic)
          @bursts.size >= MAX_KEYS || @topics.fetch(topic, 0) >= MAX_KEYS_PER_TOPIC
        end

        def start(key, length)
          @topics.compute(key.topic) { |count| count.to_i + 1 }
          schedule(key, length)
          :run
        end

        def schedule(key, length)
          @scheduler.call(length) { flush(key) }
        rescue StandardError
          forget(key)
          raise
        end

        def flush(key)
          burst = @bursts.compute_if_present(key) { |open| open.drain if open.pending? }
          return release(key.topic) unless burst

          reporting_errors { burst.flush }
          reporting_errors { schedule(key, burst.length) }
        end

        def forget(key)
          @bursts.delete(key)
          release(key.topic)
        end

        def release(topic)
          @topics.compute_if_present(topic) { |count| count - 1 if count > 1 }
        end

        def reporting_errors
          yield
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e)
        end
      end
    end
  end
end
