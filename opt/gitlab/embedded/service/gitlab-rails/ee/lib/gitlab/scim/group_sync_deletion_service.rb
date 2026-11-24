# frozen_string_literal: true

module Gitlab
  module Scim
    class GroupSyncDeletionService
      attr_reader :scim_group_uid

      def initialize(scim_group_uid:)
        @scim_group_uid = scim_group_uid
      end

      def execute
        clear_scim_group_uid_from_links

        schedule_membership_cleanup

        ServiceResponse.success
      rescue ActiveRecord::ActiveRecordError => e
        ServiceResponse.error(message: e.message)
      end

      private

      def clear_scim_group_uid_from_links
        SamlGroupLink.by_scim_group_uid(scim_group_uid).update_all(scim_group_uid: nil)
      end

      def schedule_membership_cleanup
        ::Authn::CleanupScimGroupMembershipsWorker.perform_async(scim_group_uid)
      end
    end
  end
end
