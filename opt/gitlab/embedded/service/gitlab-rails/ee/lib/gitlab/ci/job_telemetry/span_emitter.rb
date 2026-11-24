# frozen_string_literal: true

module Gitlab
  module Ci
    module JobTelemetry
      # Emits the three Rails-side OTEL spans for a CI job's lifecycle:
      #
      #   job_lifecycle  (created -> finished)
      #     |-- job_pending  (queued_at -> started_at)
      #     |-- job_running  (started_at -> finished_at)
      #
      # Span and trace IDs are deterministic so other components (Runner, Job
      # Router) can reference our spans without coordination or shared state.
      class SpanEmitter
        SPAN_KIND_LIFECYCLE = :lifecycle
        SPAN_KIND_PENDING = :pending
        SPAN_KIND_RUNNING = :running

        SPAN_NAMES = {
          SPAN_KIND_LIFECYCLE => 'job_lifecycle',
          SPAN_KIND_PENDING => 'job_pending',
          SPAN_KIND_RUNNING => 'job_running'
        }.freeze

        def initialize(job, tracer: Tracer.instance.tracer, id_generator: Tracer.instance.id_generator)
          @job = job
          @tracer = tracer
          @id_generator = id_generator
        end

        # Called from the `pending -> running` callback where started_at is set.
        # If the timestamp is missing, emission is skipped rather than fabricated.
        def emit_job_pending
          emit_span(
            SPAN_KIND_PENDING,
            parent_span_id: span_id_for(SPAN_KIND_LIFECYCLE),
            start_timestamp: job.queued_at,
            end_timestamp: job.started_at
          )
        end

        # The Runner's job_execution span is parented under this one via
        # features.tracing.span_parent_id (see EE::Ci::Build#tracing_context).
        def emit_job_running
          emit_span(
            SPAN_KIND_RUNNING,
            parent_span_id: span_id_for(SPAN_KIND_LIFECYCLE),
            start_timestamp: job.started_at,
            end_timestamp: job.finished_at,
            extra_attributes: runner_attributes
          )
        end

        # For child pipeline jobs, the parent is the trigger (bridge) job to preserve
        # correlation in the trace view. For top-level pipeline jobs, the parent is a
        # phantom placeholder (see #phantom_pipeline_parent_span_id).
        def emit_job_lifecycle(status:)
          emit_span(
            SPAN_KIND_LIFECYCLE,
            parent_span_id: bridge_span_id || phantom_pipeline_parent_span_id,
            start_timestamp: job.created_at,
            end_timestamp: job.finished_at,
            extra_attributes: {
              'ci.job.status' => status,
              'ci.pipeline.source' => job.pipeline&.source.to_s
            }
          )
        end

        # All spans across the pipeline hierarchy (parent + child pipelines) share
        # this trace_id, so they appear together in trace visualizers.
        def trace_id
          SpanIds.trace_id_for(root_pipeline_id)
        end

        # Determinism lets other components (Runner, Job Router) reference our spans
        # without coordination or persistence.
        def span_id_for(kind)
          SpanIds.for_job(root_pipeline_id, job.id, kind)
        end

        private

        attr_reader :job, :tracer, :id_generator

        def emit_span(kind, parent_span_id:, start_timestamp:, end_timestamp:, extra_attributes: {})
          return unless start_timestamp && end_timestamp

          with_deterministic_span_id(span_id_for(kind)) do
            tracer.start_span(
              SPAN_NAMES[kind],
              with_parent: parent_context(parent_span_id),
              start_timestamp: start_timestamp,
              attributes: base_attributes.merge(extra_attributes)
            ).finish(end_timestamp: end_timestamp)
          end
        rescue StandardError => e
          # Telemetry failures do not affect job outcome (graceful degradation).
          log_emission_failure(kind, e)
        end

        # Primes the id_generator with our deterministic span_id so the OTel SDK
        # uses it instead of generating a random one. Falls back to no-op (random ID)
        # when the tracer is disabled (no SDK provider available).
        def with_deterministic_span_id(hex_span_id, &block)
          return yield unless id_generator

          id_generator.with_span_id(hex_span_id, &block)
        end

        # Routes through Gitlab::ErrorTracking to get canonical exception.class /
        # exception.message log fields. Uses track_exception to surface bugs in Sentry
        def log_emission_failure(kind, error)
          ::Gitlab::ErrorTracking.track_exception(
            error,
            message: 'CI telemetry span emission failed',
            span_name: SPAN_NAMES[kind],
            job_id: job.id
          )
        end

        def root_pipeline_id
          job.pipeline&.root_ancestor&.id || job.pipeline_id
        end

        # Builds an OTel parent context that injects our deterministic trace_id
        # into the new span. Without this, the SDK would generate a random trace_id
        # for each span, and we'd lose the cross-span grouping.
        def parent_context(parent_span_id)
          span_context = ::OpenTelemetry::Trace::SpanContext.new(
            trace_id: [trace_id].pack('H*'),
            span_id: [parent_span_id].pack('H*')
          )

          ::OpenTelemetry::Trace.context_with_span(
            ::OpenTelemetry::Trace.non_recording_span(span_context)
          )
        end

        # Returns nil for top-level pipeline jobs. Bridge jobs don't currently emit
        # spans themselves; future Ci::Bridge instrumentation can use SpanIds.for_bridge
        # to produce its own job_lifecycle span_id so child pipelines correlate.
        def bridge_span_id
          bridge = job.pipeline&.source_bridge
          SpanIds.for_bridge(bridge.id) if bridge
        end

        def phantom_pipeline_parent_span_id
          SpanIds.for_pipeline_phantom(root_pipeline_id)
        end

        def base_attributes
          {
            'ci.job.id' => job.id.to_s,
            'ci.pipeline.id' => job.pipeline_id.to_s,
            'ci.project.id' => job.project_id.to_s
          }
        end

        def runner_attributes
          runner = job.runner
          return {} unless runner

          {
            'ci.runner.id' => runner.id.to_s,
            'ci.runner.type' => runner.runner_type.to_s
          }
        end
      end
    end
  end
end
