# frozen_string_literal: true

module Labkit
  module Middleware
    module Sidekiq
      module Context
        # This middleware for Sidekiq-client wraps scheduling jobs in a context
        # The context will also be added to the sidekiq job in redis so it can
        # be reinstantiated by Sidekiq-server when running the job.
        class Client
          def call(_worker_class, job, _queue, _redis_pool)
            attributes = {}

            # Don't overwrite the correlation_id from the job. A new context
            # will always generate a new correlation_id and we'd rather carry
            # through the correlation_id from the previous job if it is
            # present (eg. for retries).
            attributes[Labkit::Fields::CORRELATION_ID] = job["correlation_id"] if job["correlation_id"]

            Labkit::Context.with_context(attributes) do |context|
              job.merge!(context.to_h)

              yield
            end
          end
        end
      end
    end
  end
end
