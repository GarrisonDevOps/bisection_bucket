# frozen_string_literal: true

module Security
  module Attributes
    class UpdateProjectConnectionsService
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
        return unless project_ids.present?

        project_ids.sort.each_slice(PROJECT_BATCH_SIZE) do |project_batch|
          cleanup_mismatched_connections(project_batch)
          update_traversal_ids_for_remaining_connections(project_batch)
        end
      end

      attr_reader :project_ids, :new_root_namespace_id

      private

      def cleanup_mismatched_connections(project_batch)
        return unless new_root_namespace_id.present?

        delete_connections_for_project_batch(project_batch)
      end

      def update_traversal_ids_for_remaining_connections(project_batch)
        Project.group_by_namespace_traversal_ids(project_batch).each do |traversal_ids, batch_project_ids|
          update_connections_for_project_batch(batch_project_ids, traversal_ids)
        end
      end

      def delete_connections_for_project_batch(project_batch)
        process_project_batch(project_batch, method(:ids_to_delete_for_batch)) do |ids|
          Security::ProjectToSecurityAttribute.id_in(ids).delete_all
        end
      end

      def update_connections_for_project_batch(project_batch, traversal_ids)
        process_project_batch(project_batch, method(:ids_to_update_for_batch)) do |ids|
          Security::ProjectToSecurityAttribute.id_in(ids).update_all(traversal_ids: traversal_ids)
        end
      end

      def process_project_batch(project_batch, id_fetcher)
        last_processed_id = 0

        loop do
          ids = id_fetcher.call(project_batch, last_processed_id)
          break if ids.empty?

          yield(ids)
          last_processed_id = ids.last
        end
      end

      def ids_to_delete_for_batch(project_batch, last_processed_id)
        Security::ProjectToSecurityAttribute.by_project_id(project_batch)
          .excluding_root_namespace(new_root_namespace_id)
          .id_after(last_processed_id)
          .order_by_project_and_id
          .pluck_id(CONNECTIONS_BATCH_SIZE)
      end

      def ids_to_update_for_batch(batch_project_ids, last_processed_id)
        Security::ProjectToSecurityAttribute.by_project_id(batch_project_ids)
          .id_after(last_processed_id)
          .order_by_project_and_id
          .pluck_id(CONNECTIONS_BATCH_SIZE)
      end
    end
  end
end
