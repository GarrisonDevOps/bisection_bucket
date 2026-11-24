# frozen_string_literal: true

module Gitlab
  module SidekiqLogging
    # Lets ActiveJob jobs add extra fields to the Sidekiq done log line, like
    # ApplicationWorker#log_extra_metadata_on_done.
    #
    # Sidekiq middleware only sees the wrapper, not the ActiveJob instance, so
    # the values go through the request store, which
    # Gitlab::SidekiqMiddleware::RequestStoreMiddleware keeps around
    # Gitlab::SidekiqMiddleware::ExtraDoneLogMetadata.
    module ActiveJobLoggingExtras
      STORE_KEY = :active_job_logging_extras

      def self.logging_extras
        Gitlab::SafeRequestStore[STORE_KEY] || {}
      end

      module Job
        def log_extra_metadata_on_done(key, value)
          log_hash_metadata_on_done(key => value)
        end

        def log_hash_metadata_on_done(hash)
          extras = Gitlab::SafeRequestStore.fetch(STORE_KEY) { {} }

          hash.each { |key, value| extras[ApplicationWorker.logging_extras_key(self.class, key)] = value }
        end

        def logging_extras
          ActiveJobLoggingExtras.logging_extras
        end
      end

      module Wrapper
        def logging_extras
          ActiveJobLoggingExtras.logging_extras
        end
      end
    end
  end
end
