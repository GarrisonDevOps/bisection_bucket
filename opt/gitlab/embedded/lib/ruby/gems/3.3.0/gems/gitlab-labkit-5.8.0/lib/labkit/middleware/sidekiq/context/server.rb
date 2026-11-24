# frozen_string_literal: true

module Labkit
  module Middleware
    module Sidekiq
      module Context
        # This middleware for Sidekiq-client uses the values stored on a job to
        # reinstantiate a context in which the job will run.
        class Server
          def call(_worker_class, job, _queue)
            worker_name = (job["wrapped"].presence || job["class"]).to_s
            data = job.merge(Labkit::Context.log_key(:caller_id) => worker_name)
                      .select { |key, _| key.start_with?("#{Labkit::Context::LOG_KEY}.") || Labkit::Context::RAW_KEYS.include?(key.to_s) }

            Labkit::Context.with_context(data) do |_context|
              yield
            end
          end
        end
      end
    end
  end
end
