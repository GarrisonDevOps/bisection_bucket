# frozen_string_literal: true

module Security
  module Attributes
    class BulkUpdateSchedulerWorker
      include ApplicationWorker

      data_consistency :sticky
      feature_category :security_asset_inventories
      idempotent!

      BATCH_SIZE = 50
      BATCH_DELAY = 1.second

      def perform(group_ids, project_ids, attribute_ids, mode, user_id)
        user = User.find_by_id(user_id)
        return unless user

        all_project_ids = collect_project_ids(group_ids, project_ids, user)
        return if all_project_ids.empty?

        operation_id = create_background_operation(all_project_ids.size, attribute_ids, mode, user)
        schedule_batch_workers(all_project_ids, attribute_ids, mode, user_id, operation_id)
      end

      private

      def collect_project_ids(group_ids, project_ids, user)
        result = []

        if group_ids.present?
          authorized_groups = Group.id_in(group_ids).select { |group| Ability.allowed?(user, :read_group, group) }
          authorized_groups.each { |group| result.concat(all_project_ids(group.id)) }
        end

        if project_ids.present?
          authorized_projects = Project.id_in(project_ids).select do |project|
            Ability.allowed?(user, :read_project, project)
          end
          result.concat(authorized_projects.map(&:id))
        end

        result.uniq
      end

      def all_project_ids(group_id)
        Gitlab::Database::NamespaceProjectIdsEachBatch.new(
          group_id: group_id
        ).execute
      end

      def schedule_batch_workers(project_ids, attribute_ids, mode, user_id, operation_id)
        project_ids.in_groups_of(BATCH_SIZE, false).each_with_index do |ids_batch, index|
          # Add a small delay between batches to prevent overwhelming the queue
          delay = index * BATCH_DELAY
          Security::Attributes::BackgroundOperationBulkUpdateWorker.perform_in(
            delay,
            ids_batch,
            attribute_ids,
            mode,
            user_id,
            operation_id
          )
        end
      end

      def create_background_operation(projects_count, attribute_ids, mode, user)
        Gitlab::BackgroundOperations::RedisStore.create_operation(
          operation_type: 'attribute_update',
          user_id: user.id,
          total_items: projects_count,
          parameters: { attribute_uids: attribute_ids, mode: mode.to_s.upcase }
        )
      end
    end
  end
end
