# frozen_string_literal: true

module Search
  class NamespaceIndexIntegrityWorker
    include ApplicationWorker
    include Search::Worker
    include Gitlab::ExclusiveLeaseHelpers
    prepend ::Geo::SkipSecondary

    data_consistency :delayed

    deduplicate :until_executed, if_deduplicated: :reschedule_once
    idempotent!
    urgency :throttled

    LEASE_TIMEOUT = 30.minutes.freeze
    PROJECT_DELAY_INTERVAL = 24.hours.freeze

    BATCH_SIZE = 500
    MAX_SCHEDULED_PER_RUN = 2_000

    def perform(namespace_id, params = {})
      return if namespace_id.blank?

      namespace = Namespace.find_by_id(namespace_id)

      if namespace.nil?
        logger.warn(structured_payload(message: 'namespace not found', namespace_id: namespace_id))
        return
      end

      return unless namespace.use_elasticsearch?

      cursor = parse_cursor(params['cursor'] || params[:cursor])

      in_lock("#{self.class.name.underscore}/namespace/#{namespace_id}", ttl: LEASE_TIMEOUT) do
        process_namespace_tree(namespace, cursor)
      end
    end

    private

    def process_namespace_tree(namespace, cursor)
      cursor ||= { current_id: namespace.id, depth: [namespace.id] }
      iterator = Gitlab::Database::NamespaceEachBatch.new(
        namespace_class: Namespace,
        cursor: cursor
      )

      total_scheduled = 0
      throttled = false

      iterator.each_batch(of: BATCH_SIZE) do |ids, new_cursor|
        # Only get project namespaces since NamespaceEachBatch already walks the full subtree
        project_namespace_ids = Namespaces::ProjectNamespace.id_in(ids).pluck_primary_key

        projects_scheduled = 0
        Project.by_project_namespace(project_namespace_ids).find_each do |project|
          next unless project.should_check_index_integrity?

          ::Search::ProjectIndexIntegrityWorker.perform_in(
            rand(PROJECT_DELAY_INTERVAL),
            project.id
          )
          projects_scheduled += 1
        end

        total_scheduled += projects_scheduled

        logger.info(
          structured_payload(
            message: 'batch processed',
            namespace_id: namespace.id,
            batch_size: ids.size,
            total_scheduled: total_scheduled,
            projects_scheduled: projects_scheduled
          )
        )

        next unless total_scheduled >= MAX_SCHEDULED_PER_RUN

        logger.warn(
          structured_payload(
            message: 'throttling namespace processing, rescheduling',
            namespace_id: namespace.id,
            total_scheduled: total_scheduled,
            max_per_run: MAX_SCHEDULED_PER_RUN
          )
        )

        throttled = true
        reschedule_with_cursor(namespace.id, new_cursor)
        break
      end

      return if throttled

      logger.info(
        structured_payload(
          message: 'namespace processing completed',
          namespace_id: namespace.id,
          total_scheduled: total_scheduled
        )
      )
    end

    def reschedule_with_cursor(namespace_id, cursor)
      stringified_cursor = {
        'current_id' => cursor[:current_id],
        'depth' => cursor[:depth]
      }
      self.class.perform_in(5.minutes, namespace_id, { 'cursor' => stringified_cursor })
    end

    def parse_cursor(cursor)
      return unless cursor.is_a?(Hash)

      {
        current_id: cursor['current_id'] || cursor[:current_id],
        depth: cursor['depth'] || cursor[:depth]
      }
    end

    def logger
      @logger ||= ::Gitlab::Elasticsearch::Logger.build
    end
  end
end
