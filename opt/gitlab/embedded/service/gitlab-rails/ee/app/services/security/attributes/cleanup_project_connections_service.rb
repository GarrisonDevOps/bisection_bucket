# frozen_string_literal: true

module Security
  module Attributes
    class CleanupProjectConnectionsService
      CONNECTIONS_BATCH_SIZE = 500
      PROJECT_BATCH_SIZE = 100

      def self.execute(project_ids:, new_root_namespace_id:)
        new(project_ids: project_ids, new_root_namespace_id: new_root_namespace_id).execute
      end

      def initialize(project_ids:, new_root_namespace_id:)
        @project_ids = project_ids
        @new_root_namespace_id = new_root_namespace_id
      end

      def execute
        return 0 unless valid_request?

        cleanup_mismatched_connections
      end

      attr_reader :project_ids, :new_root_namespace_id

      private

      def valid_request?
        project_ids.present? && new_root_namespace_id.present?
      end

      def cleanup_mismatched_connections
        total = 0
        sorted_project_ids = project_ids.sort

        sorted_project_ids.each_slice(PROJECT_BATCH_SIZE) do |project_batch|
          total += delete_connections_for_project_batch(project_batch)
        end

        total
      end

      def delete_connections_for_project_batch(project_batch)
        batch_total = 0
        last_processed_id = 0

        loop do
          ids_to_delete = ids_to_delete_for_batch(project_batch, last_processed_id)
          break if ids_to_delete.empty?

          deleted_count = Security::ProjectToSecurityAttribute.id_in(ids_to_delete).delete_all
          batch_total += deleted_count
          last_processed_id = ids_to_delete.last
        end

        batch_total
      end

      def ids_to_delete_for_batch(project_batch, last_processed_id)
        Security::ProjectToSecurityAttribute.by_project_id(project_batch)
          .excluding_root_namespace(new_root_namespace_id)
          .id_after(last_processed_id)
          .order_by_project_and_id
          .pluck_id(CONNECTIONS_BATCH_SIZE)
      end
    end
  end
end
