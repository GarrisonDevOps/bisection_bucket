# frozen_string_literal: true

module Organizations
  module Groups
    class TransferWorker
      include ApplicationWorker

      data_consistency :sticky
      deduplicate :until_executed
      idempotent!

      feature_category :organization
      urgency :low

      defer_on_database_health_signal :gitlab_main, [:groups], 1.minute

      LEASE_TIMEOUT = 30.minutes.to_i

      def self.lease_key(group_id)
        "organizations_groups_transfer_worker:#{group_id}"
      end

      def perform(args)
        group_id = args['group_id']
        organization_id = args['organization_id']
        current_user_id = args['current_user_id']
        force = args['force'] || false

        group = Group.find_by_id(group_id)
        return unless group

        organization = Organization.find_by_id(organization_id)
        return unless organization

        current_user = User.find_by_id(current_user_id)
        return unless current_user

        lease_key = self.class.lease_key(group.id)
        exclusive_lease = Gitlab::ExclusiveLease.new(lease_key, uuid: jid, timeout: LEASE_TIMEOUT)

        unless obtain_lease(lease_key, exclusive_lease)
          log_lease_conflict(group, organization)
          return
        end

        begin
          Organizations::Transfer::GroupsService.new(
            group: group,
            new_organization: organization,
            current_user: current_user,
            force: force
          ).execute
        ensure
          exclusive_lease.cancel
        end
      end

      private

      # Deduplication only covers identical arguments; the lease also serialises
      # transfers of one group to different organizations.
      def obtain_lease(lease_key, exclusive_lease)
        return true if exclusive_lease.try_obtain

        # A Sidekiq interrupt retries the job with the same jid while its lease is
        # still held. The service is re-runnable, so reclaim it and continue.
        return false unless Gitlab::ExclusiveLease.get_uuid(lease_key) == jid

        exclusive_lease.cancel
        exclusive_lease.try_obtain
      end

      def log_lease_conflict(group, organization)
        Gitlab::AppLogger.warn(
          message: 'Organizations::Groups::TransferWorker skipped: a transfer for this group is already running',
          group_id: group.id,
          Labkit::Fields::GL_ORGANIZATION_ID => organization.id
        )
      end
    end
  end
end
