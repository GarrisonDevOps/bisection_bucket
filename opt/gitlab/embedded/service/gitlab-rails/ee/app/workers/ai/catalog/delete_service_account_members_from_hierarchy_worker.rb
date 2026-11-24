# frozen_string_literal: true

module Ai
  module Catalog
    class DeleteServiceAccountMembersFromHierarchyWorker
      include ApplicationWorker

      feature_category :ai_abstraction_layer
      data_consistency :delayed
      urgency :low
      idempotent!

      defer_on_database_health_signal :gitlab_main, %i[user_members users], 10.minutes

      def perform(triggering_user_id, service_account_id, group_id, members_destroy_service_options = {})
        @triggering_user = User.find_by_id(triggering_user_id)
        @service_account = User.find_by_id(service_account_id)
        @group = Group.find_by_id(group_id)
        # Since we don't necessarily have a group membership in the top level group, we have to call the service for
        # each project individually, rather than using the built in subresource handling.
        @destroy_service_options = members_destroy_service_options.symbolize_keys.merge(skip_subresources: true)

        return if triggering_user.nil? || service_account.nil? || group.nil?

        ::Ai::Catalog::ServiceAccountProjectMemberRemoveService.new(
          memberships, current_user: triggering_user, **destroy_service_options
        ).execute
      end

      private

      attr_reader :triggering_user, :service_account, :group, :destroy_service_options

      def memberships
        ::ProjectMember.in_projects(group.all_projects.select(:id)).with_user(service_account)
      end
    end
  end
end
