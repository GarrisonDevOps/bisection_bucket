# frozen_string_literal: true

# This helper is used to delete the documents from index based on schema_version value
# The index should have schema_version in the mapping

module Search
  module Elastic
    module MigrationDeleteBasedOnSchemaVersion
      include Search::Elastic::IndexName

      def migrate
        task_id = migration_state[:task_id]
        if task_id
          task_status = helper.task_status(task_id: task_id)
          if task_status['error'].present?
            set_migration_state(task_id: nil, documents_remaining: remaining_documents_count)
            log_raise 'Failed to delete', document_type: es_document_type, task_id: task_id,
              failures: task_status['error']
          end

          if task_status['completed']
            log "Removing #{es_document_type} from the original index is completed for a specific task",
              task_id: task_id
            set_migration_state(task_id: nil, documents_remaining: remaining_documents_count)
          else
            log "Removing #{es_document_type} from the original index is still in progress for a specific task",
              task_id: task_id
          end

          return
        end

        if completed?
          log 'Skipping migration since it is already applied', index_name: index_name
          return
        end

        log 'Start deleting', index_name: index_name, batch_size: batch_size
        delete_documents
        log 'Deletion batch has been processed', index_name: index_name, documents_remaining: remaining_documents_count
      end

      def completed?
        doc_count = remaining_documents_count

        log 'Checking the number of documents left with old schema_version', documents_remaining: doc_count

        doc_count == 0
      end

      def schema_version
        raise NotImplementedError
      end

      def es_document_type
        return self.class::DOCUMENT_TYPE.name.underscore if self.class.const_defined?(:DOCUMENT_TYPE)

        raise NotImplementedError
      end

      private

      def delete_documents
        response = client.delete_by_query(
          index: index_name, conflicts: 'proceed', wait_for_completion: false, max_docs: batch_size,
          body: query_with_old_schema_version
        )

        if response['failures'].present?
          log_raise "Failed to delete #{es_document_type}", failures: response['failures']
        end

        task_id = response['task']
        log "Removing #{es_document_type} from the #{index_name} index is started for a task", task_id: task_id
        set_migration_state(task_id: task_id, documents_remaining: remaining_documents_count)
      rescue StandardError => e
        set_migration_state(task_id: nil, documents_remaining: remaining_documents_count)
        raise e
      end

      def remaining_documents_count
        helper.refresh_index(index_name: index_name)
        client.count(index: index_name, body: query_with_old_schema_version)['count']
      end

      def query_with_old_schema_version
        {
          query: {
            bool: {
              minimum_should_match: 1,
              should: [
                { range: { schema_version: { lt: schema_version } } },
                { bool: { must_not: { exists: { field: 'schema_version' } } } }
              ],
              filter: { term: { type: es_document_type } }
            }
          }
        }
      end
    end
  end
end
