# frozen_string_literal: true

module Ai
  # Adds service accounts to projects as Developers with bulk inserts, so member callbacks,
  # validations and audit events are skipped. Existing memberships are skipped at any level.
  # Takes an exclusive lease per service account, so it cannot be called inside a transaction.
  class ServiceAccountProjectMemberBulkAddService
    include Gitlab::ExclusiveLeaseHelpers

    # Each batch holds one lock per project until it commits, so keep batches small.
    BATCH_SIZE = 100
    LOCK_TTL = 1.minute
    # Short polls let a waiter in a web request get the lock between a hierarchy worker's batches.
    LOCK_RETRIES = 50
    LOCK_SLEEP = 0.05.seconds

    # @param memberships [Array<Hash>] each `{ project: Project, service_account: User }`
    # @param current_user [User, nil] recorded as the creator of the added members
    def initialize(memberships, current_user: nil)
      @memberships = memberships.uniq { |membership| membership_key(membership) }
      @current_user = current_user
      @now = Time.current
    end

    def execute
      memberships_by_service_account = memberships.group_by { |membership| membership[:service_account].id }

      added = memberships_by_service_account.flat_map do |service_account_id, account_memberships|
        account_memberships.each_slice(BATCH_SIZE).flat_map do |batch|
          # members has no unique index on (source, user), so serialize check-and-insert per account.
          in_lock(lock_key(service_account_id), ttl: LOCK_TTL, retries: LOCK_RETRIES, sleep_sec: LOCK_SLEEP) do
            add_missing_members(batch)
          end
        end
      end

      ServiceResponse.success(payload: { added: added })
    end

    private

    attr_reader :memberships, :current_user, :now

    def add_missing_members(batch)
      ApplicationRecord.transaction do
        # The lease only excludes this service; members added through Members::CreatorService take these locks.
        lock_projects(batch)

        existing_keys = existing_membership_keys(batch)
        memberships_to_add = batch.reject { |membership| existing_keys.include?(membership_key(membership)) }

        insert_members(memberships_to_add)
        memberships_to_add
      end
    end

    def lock_projects(batch)
      batch.map { |membership| membership[:project] }.uniq.sort_by(&:id).each do |project|
        Member.lock_source(project) if Feature.enabled?(:lock_member_creation, project)
      end
    end

    def existing_membership_keys(batch)
      project_ids = batch.map { |membership| membership[:project].id }.uniq
      service_account_ids = batch.map { |membership| membership[:service_account].id }.uniq

      # Read from the primary so a lagging replica cannot hide members another job just inserted.
      ::Gitlab::Database::LoadBalancing::SessionMap.current(ProjectMember.load_balancer).use_primary do
        ProjectMember
          .in_projects(project_ids)
          .for_users(service_account_ids)
          .pluck(:source_id, :user_id) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- bounded by BATCH_SIZE pairs
          .to_set
      end
    end

    def insert_members(memberships_to_add)
      return if memberships_to_add.empty?

      ProjectMember.insert_all(memberships_to_add.map { |membership| member_attributes(membership) })
      ProjectAuthorization.insert_all(memberships_to_add.map { |membership| authorization_attributes(membership) })
    end

    def member_attributes(membership)
      {
        source_id: membership[:project].id,
        source_type: 'Project',
        user_id: membership[:service_account].id,
        access_level: Member::DEVELOPER,
        notification_level: NotificationSetting.levels[:global],
        created_at: now,
        updated_at: now,
        created_by_id: current_user&.id,
        state: Member::STATE_ACTIVE,
        member_namespace_id: membership[:project].project_namespace_id,
        type: 'ProjectMember'
      }
    end

    def authorization_attributes(membership)
      {
        user_id: membership[:service_account].id,
        project_id: membership[:project].id,
        access_level: Member::DEVELOPER,
        is_unique: true
      }
    end

    def membership_key(membership)
      [membership[:project].id, membership[:service_account].id]
    end

    def lock_key(service_account_id)
      "ai:service_account_project_member_bulk_add:#{service_account_id}"
    end
  end
end
