# frozen_string_literal: true

module Search
  module RakeTask
    class SemanticSearchDevSetup
      Error = Class.new(StandardError)

      DEFAULT_PROJECT_PATH = 'gitlab-duo/ai-gateway'
      FEATURE_FLAGS = %i[semantic_code_search_saas_ga].freeze
      MAX_MIGRATION_RUNS = 50
      MAX_STALLED_QUEUE_RUNS = 10
      STALLED_QUEUE_SLEEP_SECONDS = 5

      def self.setup
        new.setup
      end

      def self.index_project(project_path: nil)
        new.index_project(project_path: project_path)
      end

      def initialize
        ensure_development_environment!
      end

      # Runs the setup for the simulated instance type. Only SaaS (GITLAB_SIMULATE_SAAS=1) is supported.
      #
      # @return [void]
      def setup
        ensure_saas_mode!

        setup_saas
      end

      # Indexes a project's repository and generates its embeddings synchronously.
      #
      # @param project_path [String, nil] full path of the project; defaults to {DEFAULT_PROJECT_PATH}
      # @return [void]
      def index_project(project_path: nil)
        ensure_saas_mode!
        ensure_development_ai_gateway_url_set!

        ensure_collection_indexing!
        verify_queues_empty!

        project = fetch_project!(project_path.presence || DEFAULT_PROJECT_PATH)

        connection = Ai::ActiveContext::Connection.active
        enabled_namespace = ensure_ready_enabled_namespace(connection, project.root_namespace)
        repository = create_or_reset_repository(connection, enabled_namespace, project)

        index_repository(repository)
        process_embedding_queues
        mark_repository_as_ready(repository)
        nil
      end

      private

      def setup_saas
        logger.info(Rainbow("\nSemantic Code Search setup").yellow)

        ensure_self_hosted_aigw_url_cleared

        connection = ensure_active_connection
        run_migrations(connection)
        verify_embedding_models
        enable_feature_flags!

        logger.info(Rainbow("\nSetup complete").green)
        nil
      end

      def ensure_saas_mode!
        return if Gitlab::Utils.to_boolean(ENV['GITLAB_SIMULATE_SAAS'], default: false)

        raise Error, 'Development setup is only supported in SaaS mode (GITLAB_SIMULATE_SAAS=1).'
      end

      def ensure_development_ai_gateway_url_set!
        return if ENV['DEVELOPMENT_AI_GATEWAY_URL'].present?

        raise Error, 'DEVELOPMENT_AI_GATEWAY_URL must be set so embeddings requests reach the local AI Gateway.'
      end

      def ensure_collection_indexing!
        return if Ai::ActiveContext::Collections::Code.indexing?

        raise Error, 'Semantic Code Search indexing is not available. Run gitlab:semantic_search:setup first.'
      end

      def fetch_project!(project_path)
        logger.info(Rainbow("\nSemantic Code Search indexing: #{project_path}").yellow)

        project = Project.find_by_full_path(project_path)
        raise Error, "Project not found: #{project_path}" unless project

        project
      end

      def ensure_development_environment!
        return if Rails.env.development?

        raise Error, 'This task can only run in the development environment.'
      end

      def ensure_self_hosted_aigw_url_cleared
        unless ::Gitlab::AiGateway.has_self_hosted_ai_gateway?
          logger.info("Self-hosted AI Gateway URL:\t\tnot set (expected)")
          return
        end

        logger.warn(Rainbow(
          "Self-hosted AI Gateway URL is set (#{::Gitlab::AiGateway.self_hosted_url}). " \
            'Clearing it so the GitLab-managed embedding model migrations can run.'
        ).yellow)

        settings = Gitlab::CurrentSettings.current_application_settings
        updated = ApplicationSettings::UpdateService.new(settings, nil, { ai_gateway_url: nil }).execute

        unless updated
          raise Error, "Could not clear the self-hosted AI Gateway URL: #{settings.errors.full_messages.to_sentence}"
        end

        Gitlab::CurrentSettings.expire_current_application_settings
      end

      def ensure_active_connection
        connection = Ai::ActiveContext::Connection.active

        if connection
          verify_connection_responds!(connection)
          logger.info("Using existing active connection:\t#{connection.name}")
          return connection
        end

        create_new_connection
      end

      def create_new_connection
        Ai::ActiveContext::Connection.transaction do
          Ai::ActiveContext::ConnectionService.connect_to_advanced_search_cluster
          new_connection = Ai::ActiveContext::Connection.active
          verify_connection_responds!(new_connection)

          logger.info("Created and activated connection:\t#{new_connection.name}")
          new_connection
        end
      rescue Ai::ActiveContext::ConnectionService::ConnectionError
        raise Error, 'Could not connect to the advanced search cluster. Check that advanced search is configured ' \
          'and Elasticsearch or OpenSearch is running.'
      end

      def verify_connection_responds!(connection)
        adapter_class = connection.adapter_class.safe_constantize

        # Only Elasticsearch and OpenSearch clients support ping; other adapters are not checked
        return unless Ai::ActiveContext::Connection::ELASTICSEARCH_COMPATIBLE_ADAPTERS.value?(adapter_class)

        return if connection.adapter.client.client.ping

        raise Error, "The cluster did not respond for connection #{connection.name}."
      end

      def run_migrations(connection)
        migrations = connection.migrations

        # Migration records only exist after the worker's first run, so check after each run
        MAX_MIGRATION_RUNS.times do
          Ai::ActiveContext::MigrationWorker.new.perform

          break if migrations.failed.exists? || !migrations.processable.exists?
        end

        failed_versions = migrations.failed.pluck(:version) # rubocop:disable CodeReuse/ActiveRecord -- scoped to connection's AR association
        raise Error, "Migrations failed: #{failed_versions.join(', ')}" if failed_versions.any?
        raise Error, "Migrations did not complete after #{MAX_MIGRATION_RUNS} runs" if migrations.processable.exists?

        logger.info("Migrations:\t\t\t\t#{Rainbow('complete').green}")
      end

      def verify_embedding_models
        # Reset cache before fetching the collection_record through the collection
        ::ActiveContext::CollectionCache.reset
        collection = Ai::ActiveContext::Collections::Code.collection_record

        missing_models = %i[current_indexing_embedding_model search_embedding_model].reject do |model|
          collection&.public_send(model).present? # rubocop:disable GitlabSecurity/PublicSend -- fixed list of attributes
        end
        return if missing_models.empty?

        raise Error, "The code collection has no #{missing_models.join(' or ')} after running migrations."
      end

      def enable_feature_flags!
        FEATURE_FLAGS.each do |flag|
          Feature.enable(flag)
          logger.info("Enabled feature flag:\t\t\t#{flag}")
        end
      end

      def verify_queues_empty!
        queue_sizes = ActiveContext::Queues.queue_counts
          .group_by { |queue_count| queue_count[:queue_name] }
          .transform_values { |counts| counts.sum { |queue_count| queue_count[:count] } }
        queue_sizes[ActiveContext::DeadQueue.name] = ActiveContext::DeadQueue.queue_size

        non_empty_queues = queue_sizes.select { |_name, size| size > 0 }
        return if non_empty_queues.empty?

        details = non_empty_queues.map { |name, size| "#{name}: #{size}" }.join(', ')
        raise Error, "All ActiveContext queues must be empty before indexing. Non-empty queues: #{details}"
      end

      def ensure_ready_enabled_namespace(connection, namespace)
        enabled_namespace = Ai::ActiveContext::Code::EnabledNamespace.find_enabled_namespace(connection, namespace)

        if enabled_namespace&.ready?
          action = 'already ready'
        elsif enabled_namespace
          enabled_namespace.ready!
          action = 'marked as ready'
        else
          enabled_namespace = connection.enabled_namespaces.create!(namespace: namespace, state: :ready)
          action = 'created'
        end

        logger.info("Enabled namespace:\t\t\t#{namespace.full_path} (id=#{enabled_namespace.id}, #{action})")
        enabled_namespace
      end

      def create_or_reset_repository(connection, enabled_namespace, project)
        repository = connection.repositories.for_project(project.id).first

        if repository
          # Resetting to pending makes the indexer run a full initial index instead of an incremental one
          repository.update!(state: :pending, enabled_namespace: enabled_namespace, last_commit: nil, metadata: {})
          action = 'reset'
        else
          repository = connection.repositories.create!(
            project: project, enabled_namespace: enabled_namespace, state: :pending
          )
          action = 'created'
        end

        logger.info("Repository record:\t\t\tid=#{repository.id} (#{action})")
        repository
      end

      def index_repository(repository)
        logger.info('Indexing repository...')
        Ai::ActiveContext::Code::RepositoryIndexWorker.new.perform(repository.id)
        repository.reset

        return if repository.embedding_indexing_in_progress? || repository.ready?

        raise Error, "Repository indexing failed with state #{repository.state}: #{repository.last_error}"
      end

      def process_embedding_queues
        logger.info('Generating embeddings...')

        start_time = Gitlab::Metrics::System.monotonic_time
        previous_queue_size = Ai::ActiveContext::Queues::Code.queue_size

        logger.info("Initial queue size:\t\t\t#{previous_queue_size}")

        stalled_runs = 0

        loop do
          ActiveContext.execute_all_queues!
          elapsed_s = (Gitlab::Metrics::System.monotonic_time - start_time).round(1)

          # Tested locally that synchronous processing will not result in failed refs moved to the RetryQueue.
          # For now, fail the run early if the retry queues get populated, as that is unexpected.
          # IF we encounter a different behavior, a future iteration could process the retry queues instead.
          ensure_no_failed_refs!

          current_queue_size = Ai::ActiveContext::Queues::Code.queue_size
          logger.info("Processed embeddings:\t\t\t" \
            "processed: #{previous_queue_size - current_queue_size}, " \
            "queue after: #{current_queue_size} (elapsed: #{elapsed_s}s)")

          break if current_queue_size == 0

          # Bound the loop, so an unattended run cannot spin forever
          if current_queue_size < previous_queue_size
            stalled_runs = 0
          else
            stalled_runs += 1
            if stalled_runs >= MAX_STALLED_QUEUE_RUNS
              raise Error, "The code queue did not shrink in #{MAX_STALLED_QUEUE_RUNS} runs " \
                "(size: #{current_queue_size}). Check log/active_context.log."
            end

            sleep STALLED_QUEUE_SLEEP_SECONDS
          end

          previous_queue_size = current_queue_size
        end

        total_duration_s = (Gitlab::Metrics::System.monotonic_time - start_time).round(1)
        logger.info("Embeddings generated in:\t\t#{total_duration_s}s")
      end

      def ensure_no_failed_refs!
        retry_queue_size = ActiveContext::Queues.retry_chain.sum(&:queue_size)
        return if retry_queue_size == 0

        raise Error, "Embeddings generation failed for #{retry_queue_size} documents, which were moved to " \
          'the retry queues. Check log/active_context.log.'
      end

      def mark_repository_as_ready(repository)
        Ai::ActiveContext::Code::MarkRepositoryAsReadyEventWorker.new.handle_event(
          Ai::ActiveContext::Code::MarkRepositoryAsReadyEvent.build
        )
        repository.reset

        raise Error, "Repository was not marked as ready, its state is #{repository.state}" unless repository.ready?

        logger.info(Rainbow("\nIndexing complete: repository is ready").green)
      end

      def logger
        @logger ||= Logger.new($stdout).tap do |logger|
          logger.formatter = ->(_severity, _datetime, _progname, msg) { "#{msg}\n" }
        end
      end
    end
  end
end
