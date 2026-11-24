# frozen_string_literal: true

module Ai
  module Catalog
    class AddInheritedServiceAccountMembersToHierarchyWorker
      include ApplicationWorker

      BATCH_SIZE = 100
      # Pause between batches so a trigger waiting on the same service account lock can take it.
      BATCH_SLEEP = 0.1.seconds

      feature_category :ai_catalog_curation
      data_consistency :delayed
      urgency :low
      idempotent!
      concurrency_limit -> { 10 }

      defer_on_database_health_signal :gitlab_main, %i[members project_authorizations], 10.minutes

      def perform(triggering_user_id, item_consumer_id, _params = {})
        @triggering_user = User.find_by_id(triggering_user_id)
        @item_consumer_id = item_consumer_id

        item_consumer = ::Ai::Catalog::ItemConsumer.find_by_id(item_consumer_id)
        # The cleanup below needs a user, so don't add members we could not remove again.
        return if triggering_user.nil? || item_consumer.nil?
        return unless item_consumer.inheritance? && item_consumer.service_account

        @group = item_consumer.group
        @service_account = item_consumer.service_account

        project_namespace_iterator.each_batch(of: BATCH_SIZE) do |project_namespace_ids|
          break if enablement_removed?

          add_members(Project.by_project_namespace(project_namespace_ids))
          sleep(BATCH_SLEEP)
        end

        remove_added_members if enablement_removed?
      end

      private

      attr_reader :triggering_user, :item_consumer_id, :group, :service_account

      def project_namespace_iterator
        cursor = { current_id: group.id, depth: [group.id] }
        Gitlab::Database::NamespaceEachBatch.new(namespace_class: Namespaces::ProjectNamespace, cursor: cursor)
      end

      def add_members(projects)
        memberships = projects.map { |project| { project: project, service_account: service_account } }

        ::Ai::ServiceAccountProjectMemberBulkAddService.new(memberships, current_user: triggering_user).execute
      end

      # Re-read on every batch so a disable during the run stops the fan-out.
      def enablement_removed?
        !::Ai::Catalog::ItemConsumer
          .inherited_with_service_account_for(group)
          .for_service_account(service_account.id)
          .id_in(item_consumer_id)
          .exists?
      end

      # The enablement was removed while this job ran, so its own cleanup may have missed the
      # memberships added here.
      def remove_added_members
        ::Ai::Catalog::DeleteServiceAccountMembersFromHierarchyWorker.perform_async(
          triggering_user.id, service_account.id, group.id, { 'skip_authorization' => true }
        )
      end
    end
  end
end
