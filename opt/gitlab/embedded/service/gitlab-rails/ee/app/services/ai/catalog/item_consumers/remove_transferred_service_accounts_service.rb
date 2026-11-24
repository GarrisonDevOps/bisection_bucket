# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      # Removes the old top-level group's flow service accounts from a project that was transferred
      # out of it, and deactivates the project's triggers of that group's direct configurations.
      class RemoveTransferredServiceAccountsService
        def initialize(project:, old_root_namespace_id:, current_user:)
          @project = project
          @old_root_namespace_id = old_root_namespace_id
          @current_user = current_user
        end

        def execute
          ::Ai::FlowTrigger.by_item_consumer_ids(direct_consumers.select(:id)).update_all(active: false)

          memberships = ::ProjectMember.in_projects(project.id).for_users(old_group_service_account_ids)

          ::Ai::Catalog::ServiceAccountProjectMemberRemoveService.new(
            memberships, current_user: current_user, skip_authorization: true, skip_subresources: true
          ).execute

          ServiceResponse.success
        end

        private

        attr_reader :project, :old_root_namespace_id, :current_user

        def direct_consumers
          ::Ai::Catalog::ItemConsumer
            .for_projects(project)
            .with_parent_on_groups(old_root_namespace_id)
            .excluding_foundational_flows
        end

        def old_group_service_account_ids
          ::Ai::Catalog::ItemConsumer
            .for_groups_with_service_account(old_root_namespace_id)
            .excluding_foundational_flows
            .select(:service_account_id)
        end
      end
    end
  end
end
