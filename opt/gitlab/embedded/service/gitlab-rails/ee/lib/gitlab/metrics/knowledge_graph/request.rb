# frozen_string_literal: true

module Gitlab
  module Metrics
    module KnowledgeGraph
      module Request
        DURATION_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0].freeze
        COUNT_BUCKETS = [1, 5, 10, 25, 50, 100, 250, 500, 1000].freeze

        HISTOGRAMS = {
          gitlab_knowledge_graph_grpc_duration_seconds: {
            description: 'Duration of gRPC calls from Rails to GKG',
            buckets: DURATION_BUCKETS
          },
          gitlab_knowledge_graph_redaction_duration_seconds: {
            description: 'Duration of RedactionService.execute (resource loading + ability checks)',
            buckets: DURATION_BUCKETS
          },
          gitlab_knowledge_graph_redaction_batch_size: {
            description: 'Number of resources evaluated per redaction batch',
            buckets: COUNT_BUCKETS
          },
          gitlab_knowledge_graph_redaction_filtered_count: {
            description: 'Number of resources denied per redaction batch',
            buckets: COUNT_BUCKETS
          },
          gitlab_knowledge_graph_jwt_build_duration_seconds: {
            description: 'Duration of JWT token generation including auth context',
            buckets: DURATION_BUCKETS
          },
          gitlab_knowledge_graph_auth_context_duration_seconds: {
            description: 'Duration of authorization context traversal ID computation',
            buckets: DURATION_BUCKETS
          }
        }.freeze

        COUNTERS = {
          gitlab_knowledge_graph_grpc_errors_total: {
            description: 'Total gRPC errors from Rails to GKG by method and code'
          }
        }.freeze

        class << self
          def measure(histogram_name, labels = {})
            start = ::Gitlab::Metrics::System.monotonic_time
            result = yield
            duration = ::Gitlab::Metrics::System.monotonic_time - start
            fetch_histogram(histogram_name).observe(labels, duration)
            result
          end

          def observe_grpc_duration(method, status, duration)
            fetch_histogram(:gitlab_knowledge_graph_grpc_duration_seconds)
              .observe({ method: method, status: status }, duration)
          end

          def observe_redaction_duration(duration)
            fetch_histogram(:gitlab_knowledge_graph_redaction_duration_seconds)
              .observe({}, duration)
          end

          def observe_redaction_batch_size(count)
            fetch_histogram(:gitlab_knowledge_graph_redaction_batch_size)
              .observe({}, count)
          end

          def observe_redaction_filtered(count)
            fetch_histogram(:gitlab_knowledge_graph_redaction_filtered_count)
              .observe({}, count)
          end

          def observe_jwt_duration(duration)
            fetch_histogram(:gitlab_knowledge_graph_jwt_build_duration_seconds)
              .observe({}, duration)
          end

          def observe_auth_context_duration(duration)
            fetch_histogram(:gitlab_knowledge_graph_auth_context_duration_seconds)
              .observe({}, duration)
          end

          def increment_grpc_error(method, code)
            fetch_counter(:gitlab_knowledge_graph_grpc_errors_total)
              .increment({ method: method, code: code })
          end

          private

          def fetch_histogram(name)
            @histograms ||= {}
            @histograms[name] ||= begin
              config = HISTOGRAMS.fetch(name)
              ::Gitlab::Metrics.histogram(name, config[:description], {}, config[:buckets])
            end
          end

          def fetch_counter(name)
            @counters ||= {}
            @counters[name] ||= begin
              config = COUNTERS.fetch(name)
              ::Gitlab::Metrics.counter(name, config[:description])
            end
          end
        end
      end
    end
  end
end
