# frozen_string_literal: true

require "opentracing"

module Labkit
  module Middleware
    module Sidekiq
      module Tracing
        # Server provides a sidekiq server middleware for
        # instrumenting distributed tracing calls when they are
        # executed by the Sidekiq server
        class Server
          include SidekiqCommon

          SPAN_KIND = "server"

          def call(_worker, job, _queue)
            context = Labkit::Tracing::TracingUtils.tracer.extract_context(job)

            Labkit::Tracing::TracingUtils.with_tracing(operation_name: "sidekiq:#{job_class(job)}", child_of: context, tags: tags_from_job(job, SPAN_KIND)) { |_span| yield }
          end
        end
      end
    end
  end
end
