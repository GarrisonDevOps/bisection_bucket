# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      # Queues syncing the flow service accounts of projects that moved from one top-level group
      # to another, when the old group has flow configurations or the new group grants access.
      class SyncTransferredProjectsService
        BATCH_SIZE = 100

        # @param projects [ActiveRecord::Relation<Project>] the transferred projects
        def initialize(projects, old_root_namespace_id:, new_root_namespace_id:, current_user:)
          @projects = projects
          @old_root_namespace_id = old_root_namespace_id
          @new_root_namespace_id = new_root_namespace_id
          @current_user = current_user
        end

        def execute
          return ServiceResponse.success unless sync_needed?

          params = { 'old_root_namespace_id' => old_root_namespace_id }
          new_root_namespace = ::Namespace.find_by_id(new_root_namespace_id)

          SyncProjectServiceAccountsWorker.bulk_perform_async_with_contexts(
            project_id_batches,
            arguments_proc: ->(project_ids) { [current_user.id, project_ids, params] },
            context_proc: ->(_) { { namespace: new_root_namespace } }
          )

          ServiceResponse.success
        end

        private

        attr_reader :projects, :old_root_namespace_id, :new_root_namespace_id, :current_user

        def project_id_batches
          batches = []
          projects.each_batch(of: BATCH_SIZE) { |batch| batches << batch.pluck_primary_key }
          batches
        end

        def sync_needed?
          return false if old_root_namespace_id == new_root_namespace_id
          return true if ItemConsumer.for_groups_with_service_account(old_root_namespace_id).exists?

          ::Feature.enabled?(:ai_catalog_group_inherited_consumers, ::Group.actor_from_id(new_root_namespace_id)) &&
            ItemConsumer.inherited_with_service_account_for(new_root_namespace_id).exists?
        end
      end
    end
  end
end
