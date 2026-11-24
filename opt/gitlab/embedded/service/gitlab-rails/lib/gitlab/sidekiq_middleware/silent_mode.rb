# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    class SilentMode
      def call(worker, job, queue)
        yield
      rescue StandardError => error
        raise unless Rails.env.production? && silent_mode_blocked?(error)

        payload = {
          message: 'Job blocked by Silent Mode',
          class: worker.class.name,
          jid: job['jid'],
          queue: queue
        }
        Gitlab::ExceptionLogFormatter.format!(error, payload)

        Sidekiq.logger.warn(payload)
      end

      private

      def silent_mode_blocked?(error)
        while error
          return true if error.is_a?(Gitlab::HTTP_V2::SilentModeBlockedError)

          error = error.cause
        end

        false
      end
    end
  end
end
