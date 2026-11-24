# frozen_string_literal: true

module Gitlab
  module Ci
    module JobTelemetry
      # Trace and span ID derivation for CI job telemetry.
      #
      # Delegates shared formulas to +Gitlab::Ci::TraceContext+ (CE) to
      # guarantee all systems produce identical values. Only
      # +for_pipeline_phantom+ remains EE-specific.
      #
      # OTel spec: trace_id is 16 bytes (32 hex chars), span_id is 8 bytes (16 hex chars).
      # https://opentelemetry.io/docs/specs/otel/trace/api/#spancontext
      module SpanIds
        class << self
          # Trace ID derived from the root pipeline's database ID. All spans across
          # the pipeline hierarchy (parent + child pipelines) share this trace_id.
          def trace_id_for(root_pipeline_id)
            ::Gitlab::Ci::TraceContext.trace_id_for(root_pipeline_id)
          end

          # Span ID for a job's lifecycle/pending/running spans.
          # +kind+ is one of SpanEmitter::SPAN_KIND_*.
          def for_job(root_pipeline_id, job_id, kind)
            ::Gitlab::Ci::TraceContext.span_id_for_job(root_pipeline_id, job_id, kind)
          end

          # Span ID used as the parent for top-level pipeline job_lifecycle spans.
          # Never emitted as a real span; trace visualizers will show this as a
          # "missing parent", which is the expected behavior.
          #
          # This remains EE-only. It uses a single-ID formula specific to
          # the phantom parent pattern (distinct from TraceContext.span_id_for_pipeline).
          def for_pipeline_phantom(root_pipeline_id)
            ::OpenSSL::Digest::SHA256.hexdigest(
              "pipeline:#{root_pipeline_id}"
            )[0, ::Gitlab::Ci::TraceContext::SPAN_ID_HEX_LENGTH]
          end

          # Span ID derived from a trigger (bridge) job's database ID. Used to nest
          # child pipeline jobs under the bridge in the trace view.
          def for_bridge(bridge_id)
            ::Gitlab::Ci::TraceContext.span_id_for_bridge(bridge_id)
          end
        end
      end
    end
  end
end
