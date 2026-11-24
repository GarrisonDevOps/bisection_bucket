# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      class SyncProjectServiceAccountsWorker
        include ApplicationWorker

        feature_category :ai_catalog_curation
        data_consistency :delayed
        urgency :low
        idempotent!
        concurrency_limit -> { 10 }

        defer_on_database_health_signal :gitlab_main, %i[members project_authorizations], 10.minutes

        def perform(user_id, project_ids, params = {})
          user = User.find_by_id(user_id)
          return unless user

          projects = ::Project.id_in(project_ids).to_a
          old_root_namespace_id = params['old_root_namespace_id']

          remove_old_group_service_accounts(projects, old_root_namespace_id, user) if old_root_namespace_id

          AddInheritedServiceAccountsService.new(projects: projects, current_user: user).execute
        end

        private

        def remove_old_group_service_accounts(projects, old_root_namespace_id, user)
          root_ids_by_project_id = ::Project.root_namespace_ids_by_project_ids(projects.map(&:id))

          projects.each do |project|
            next if root_ids_by_project_id[project.id] == old_root_namespace_id

            RemoveTransferredServiceAccountsService.new(
              project: project, old_root_namespace_id: old_root_namespace_id, current_user: user
            ).execute
          end
        end
      end
    end
  end
end
