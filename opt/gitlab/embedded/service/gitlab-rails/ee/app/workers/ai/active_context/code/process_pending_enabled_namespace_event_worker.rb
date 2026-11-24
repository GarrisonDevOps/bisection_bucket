# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class ProcessPendingEnabledNamespaceEventWorker
        include Gitlab::EventStore::Subscriber
        include Gitlab::Utils::StrongMemoize
        prepend ::Geo::SkipSecondary
        include ApplicationWorker

        feature_category :semantic_code_search
        deduplicate :until_executed
        data_consistency :sticky
        urgency :low
        idempotent!
        defer_on_database_health_signal :gitlab_main,
          [:p_ai_active_context_code_enabled_namespaces, :p_ai_active_context_code_repositories],
          10.minutes

        def handle_event(_)
          return false unless ::Ai::ActiveContext::Collections::Code.indexing?

          process_next_namespace
        end

        private

        def process_next_namespace
          enabled_namespace = Ai::ActiveContext::Code::EnabledNamespace.pending.with_active_connection.first

          return unless enabled_namespace

          success = process_projects_for_namespace(enabled_namespace)

          enabled_namespace.ready! if success

          return unless Ai::ActiveContext::Code::EnabledNamespace.pending.with_active_connection.exists?

          reemit_event
        end

        def process_projects_for_namespace(enabled_namespace)
          existing_repository_project_ids = existing_repository_project_ids_for(enabled_namespace)

          total_count = 0
          all_successful = true

          projects_for_namespace(enabled_namespace) do |projects_batch|
            records_to_insert = eligible_projects(projects_batch, existing_repository_project_ids, enabled_namespace)

            next if records_to_insert.empty?

            success = bulk_create_repositories(records_to_insert)
            all_successful = false unless success
            total_count += records_to_insert.size
          end

          log_hash_metadata_on_done(repositories_created: total_count, enabled_namespace_id: enabled_namespace.id)

          all_successful
        end

        def existing_repository_project_ids_for(enabled_namespace)
          project_ids = Set.new

          Ai::ActiveContext::Code::Repository
            .for_connection_and_enabled_namespace(connection, enabled_namespace)
            .select(:project_id)
            .each_batch(column: :project_id) { |batch| project_ids.merge(batch.map(&:project_id)) }

          project_ids
        end

        def projects_for_namespace(enabled_namespace)
          project_namespaces = ::Namespace.by_root_id(enabled_namespace.namespace_id).project_namespaces

          project_namespaces.each_batch do |project_namespaces_batch|
            projects_batch = ::Project
              .by_project_namespace(project_namespaces_batch.select(:id))
              .includes(:route, :project_setting, project_namespace: [:route]) # rubocop: disable CodeReuse/ActiveRecord -- need to include to pevent N+1 queries

            yield projects_batch if block_given?
          end
        end

        def eligible_projects(projects, existing_project_ids, enabled_namespace)
          records = []

          projects.each do |project|
            next if existing_project_ids.include?(project.id)
            next unless project.project_setting.duo_features_enabled

            records << {
              project_id: project.id,
              enabled_namespace_id: enabled_namespace.id,
              connection_id: connection.id
            }
          end

          records
        end

        def bulk_create_repositories(data)
          return true if data.empty?

          results = Ai::ActiveContext::Code::Repository.create(data)

          log_errors(results)

          results.all?(&:persisted?)
        end

        def log_errors(results)
          results.each do |result|
            next if result.persisted?

            logger.warn(
              structured_payload(
                message: 'Failed to create Ai::ActiveContext::Code::Repository',
                project_id: result.project_id,
                enabled_namespace_id: result.enabled_namespace_id,
                connection_id: result.connection_id,
                errors: result.errors.full_messages
              ))
          end
        end

        def connection
          Ai::ActiveContext::Connection.active
        end
        strong_memoize_attr :connection

        def reemit_event
          Gitlab::EventStore.publish(ProcessPendingEnabledNamespaceEvent.build)
        end
      end
    end
  end
end
