# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      # Adds the service accounts of the inheritance consumers on each project's top-level group
      # to that project.
      class AddInheritedServiceAccountsService
        def initialize(projects:, current_user:)
          @projects = projects.to_a
          @current_user = current_user
        end

        def execute
          memberships = projects.flat_map do |project|
            service_accounts_by_root_id.fetch(root_ids_by_project_id[project.id], []).map do |service_account|
              { project: project, service_account: service_account }
            end
          end

          ::Ai::ServiceAccountProjectMemberBulkAddService.new(memberships, current_user: current_user).execute
        end

        private

        attr_reader :projects, :current_user

        def root_ids_by_project_id
          @root_ids_by_project_id ||= ::Project.root_namespace_ids_by_project_ids(projects.map(&:id))
        end

        def service_accounts_by_root_id
          @service_accounts_by_root_id ||= ::Ai::Catalog::ItemConsumer
            .inherited_with_service_account_for(enabled_root_ids)
            .with_service_account
            .group_by(&:group_id)
            .transform_values { |consumers| consumers.map(&:service_account) }
        end

        def enabled_root_ids
          root_ids_by_project_id.values.uniq.select do |root_id|
            ::Feature.enabled?(:ai_catalog_group_inherited_consumers, ::Group.actor_from_id(root_id))
          end
        end
      end
    end
  end
end
