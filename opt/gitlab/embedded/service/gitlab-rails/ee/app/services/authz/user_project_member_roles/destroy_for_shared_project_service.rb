# frozen_string_literal: true

module Authz
  module UserProjectMemberRoles
    class DestroyForSharedProjectService < BaseService
      attr_reader :shared_project, :shared_with_group

      BATCH_SIZE = 1_000

      def initialize(shared_project, shared_with_group)
        @shared_project = shared_project
        @shared_with_group = shared_with_group
        @deleted_count = 0
      end

      def execute
        ::Authz::UserProjectMemberRole
          .in_project_shared_with_group(shared_project, shared_with_group)
          .each_batch(of: BATCH_SIZE) do |batch|
            @deleted_count += batch.delete_all
          end

        log
      end

      private

      def log
        Gitlab::AppJsonLogger.info(
          class: self.class.name,
          shared_project_id: @shared_project.id,
          shared_with_group_id: @shared_with_group.id,
          'update_user_project_member_roles.event': 'project_group_link deleted',
          'update_user_project_member_roles.upserted_count': 0,
          'update_user_project_member_roles.deleted_count': @deleted_count
        )
      end
    end
  end
end
