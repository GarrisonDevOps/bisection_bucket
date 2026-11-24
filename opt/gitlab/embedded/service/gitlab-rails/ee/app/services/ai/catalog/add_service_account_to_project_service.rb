# frozen_string_literal: true

module Ai
  module Catalog
    # Adds a flow service account to a project as a Developer. An existing membership is kept at its current role.
    class AddServiceAccountToProjectService
      def initialize(service_account, project, current_user:)
        @service_account = service_account
        @project = project
        @current_user = current_user
      end

      def execute
        return ServiceResponse.success if project.team.member?(service_account)

        response = add_member

        # The membership check above caches the miss for the rest of the request, which would fail
        # later permission checks. Purge on lock failure too, as the lock holder may have added it.
        # See https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254154
        project.team.purge_member_access_cache_for_user_id(service_account.id)

        response
      end

      private

      attr_reader :service_account, :project, :current_user

      def add_member
        ::Ai::ServiceAccountProjectMemberBulkAddService.new(
          [{ project: project, service_account: service_account }], current_user: current_user
        ).execute

        ServiceResponse.success
      rescue ::Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError => e
        ServiceResponse.error(message: e.message, reason: :failed_to_obtain_lock)
      end
    end
  end
end
