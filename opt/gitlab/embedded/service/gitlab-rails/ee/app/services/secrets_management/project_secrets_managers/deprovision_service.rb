# frozen_string_literal: true

module SecretsManagement
  module ProjectSecretsManagers
    class DeprovisionService < BaseDeprovisionService
      private

      def lease_key_prefix
        'project_secret_operation'
      end

      def entity_path
        maintenance_task.project_path
      end

      # The SM is normally already gone by the time the worker runs
      # (destroyed by the service inline, or cascade-deleted by parent
      # destroy). When the row does still exist - rare edge case of a
      # partial earlier run - `project_id` is now NOT NULL so we can
      # look it up directly without the cached-path detour the
      # pre-trigger design needed.
      def find_secrets_manager
        ProjectSecretsManager.find_by_project_id(maintenance_task.project_id)
      end

      def payload_key
        :project_secrets_manager_maintenance_task
      end

      def execute_deprovision
        namespace_id = find_secrets_manager&.namespace_id_for_secret_count
        response = super
        enqueue_namespace_secret_count_refresh(namespace_id) if response&.success?
        response
      end

      def enqueue_namespace_secret_count_refresh(namespace_id)
        return unless namespace_id

        ReconcileNamespaceSecretCountWorker.perform_async(namespace_id, current_user&.id)
      end
    end
  end
end
