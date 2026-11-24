# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class IndexerBase
        include Gitlab::Utils::StrongMemoize
        include Ai::ActiveContext::Concerns::Loggable

        # Keep below the LEASE_TTL of the workers that run the indexer, so the lease
        # outlives the subprocess and no second run starts against the same project.
        # Revisit in https://gitlab.com/gitlab-org/gitlab/-/work_items/630736
        TIMEOUT = '45m'
        Error = Class.new(StandardError)
        # A deploy signal killed the subprocess. Not a real failure.
        # RetryError lets Sidekiq retry as usual. Sentry never sees it (see Gitlab::ErrorTracking#before_send).
        Interrupted = Class.new(Gitlab::SidekiqMiddleware::RetryError)

        def initialize(active_context_repository)
          # `active_context_repository` refers to `Ai::ActiveContext::Code::Repository`
          # object used for tracking the state of embeddings indexing for a project
          # `project_repository` refers to the `Repository` object that points to the
          # actual git repository in Gitaly.
          @active_context_repository = active_context_repository
          @project = active_context_repository.project
          @project_repository = project&.repository
        end

        private

        attr_reader :active_context_repository, :project, :project_repository

        def command
          [
            Gitlab.config.elasticsearch.indexer_path,
            '-adapter', adapter.name,
            '-connection', ::Gitlab::Json.generate(connection),
            '-options', ::Gitlab::Json.generate(options)
          ]
        end

        def environment_variables
          { 'GITLAB_INDEXER_MODE' => 'chunk' }
        end

        def connection
          adapter.indexer_connection_options
        end

        def base_options
          {
            project_id: active_context_repository.project_id,
            partition_name: collection_class.partition_name,
            partition_number: collection_class.partition_number(active_context_repository.project_id),
            timeout: TIMEOUT
          }
        end

        def collection_class
          ::Ai::ActiveContext::Collections::Code
        end

        def adapter
          ::ActiveContext.adapter
        end
        strong_memoize_attr :adapter

        def log_duration(message, extra_params = {})
          result = nil

          duration = Benchmark.realtime do
            result = yield
          end

          extra_params[:duration_s] = duration.round(2)
          log_info(message, extra_params)

          result
        end

        def log_info(message, extra_params = {})
          logger.info(build_log_payload(message, extra_params))
        end

        def log_error(message, extra_params = {})
          logger.error(build_log_payload(message, extra_params))
        end

        def build_log_payload(message, extra_params = {})
          params = {
            message: message,
            ai_active_context_code_repository_id: active_context_repository.id,
            Labkit::Fields::GL_PROJECT_ID => active_context_repository.project_id
          }.merge(extra_params)

          build_structured_payload(**params)
        end
      end
    end
  end
end
