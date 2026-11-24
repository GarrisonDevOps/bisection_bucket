# frozen_string_literal: true

require "opentracing"

module Labkit
  module Middleware
    module Sidekiq
      module Tracing
        # Client provides a sidekiq client middleware for
        # instrumenting distributed tracing calls made from the client
        # application
        class Client
          include SidekiqCommon

          SPAN_KIND = "client"

          def call(_worker_class, job, _queue, _redis_pool)
            Labkit::Tracing::TracingUtils.with_tracing(operation_name: "sidekiq:#{job_class(job)}", tags: tags_from_job(job, SPAN_KIND)) do |span|
              # Inject the details directly into the job
              Labkit::Tracing::TracingUtils.tracer.inject_context(span, job)

              yield
            end
          end
        end
      end
    end
  end
end
