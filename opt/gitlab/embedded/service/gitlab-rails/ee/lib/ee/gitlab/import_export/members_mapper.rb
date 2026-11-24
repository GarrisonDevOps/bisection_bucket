# frozen_string_literal: true

module EE
  module Gitlab
    module ImportExport
      module MembersMapper
        extend ::Gitlab::Utils::Override

        # The archive is user-editable; keep only attributes that cannot create requests, invites or LDAP overrides.
        ENTERPRISE_MEMBER_KEYS = %w[
          access_level expires_at created_at updated_at created_by_id notification_level user
        ].freeze

        MAPPING_PATH_NONE = 'none'
        MAPPING_PATH_ENTERPRISE_OWNER = 'enterprise_owner'
        MAPPING_PATH_MEMBERSHIP_LOCKED = 'membership_locked'
        MAPPING_PATH_SEAT_LIMIT_EXCEEDED = 'seat_limit_exceeded'

        EMAIL_BATCH_SIZE = 1_000

        private

        # rubocop:disable Gitlab/ModuleWithInstanceVariables -- CE MembersMapper has no readers for @user and @importable
        override :determine_exported_members
        def determine_exported_members(exported_members)
          return super if @user.admin? # rubocop:disable Cop/UserAdmin -- keeps the CE admin gate unchanged
          return [] unless ::Feature.enabled?(:file_import_enterprise_user_mapping, importable_root_ancestor)

          unless enterprise_owner_import?
            log_enterprise_mapping_summary(MAPPING_PATH_NONE, exported_members.size, 0, 0)
            return []
          end

          members_with_users = enterprise_members(exported_members)
          mapping_path = enterprise_mapping_path(members_with_users)
          @skip_enterprise_memberships = mapping_path != MAPPING_PATH_ENTERPRISE_OWNER
          members = members_with_users.map(&:first)

          log_enterprise_mapping_summary(mapping_path, exported_members.size, members.size,
            @skip_enterprise_memberships ? members.size : 0)

          members
        end

        # Over a limit, contributions still map to the enterprise users but no memberships are created.
        override :add_team_member
        def add_team_member(member, existing_user_id = nil)
          return true if @skip_enterprise_memberships

          super
        end

        # Reuse the batched enterprise lookup; CE would query every mapped email in one IN list.
        override :existing_users_email_map
        def existing_users_email_map
          @enterprise_users_email_map || super
        end

        def enterprise_mapping_path(members_with_users)
          return MAPPING_PATH_MEMBERSHIP_LOCKED if @importable.membership_locked?
          return MAPPING_PATH_SEAT_LIMIT_EXCEEDED unless enterprise_seats_available?(members_with_users)

          MAPPING_PATH_ENTERPRISE_OWNER
        end

        def enterprise_seats_available?(members_with_users)
          seat_overages = ::GitlabSubscriptions::MemberManagement::BlockSeatOverages
          return true unless seat_overages.block_seat_overages?(@importable)

          # Billing counts only active users, so deactivated users take no seat.
          billable = members_with_users.reject do |member, user|
            user.deactivated? ||
              seat_overages.non_billable_member?(importable_root_ancestor, member['access_level'], nil)
          end
          return true if billable.empty?

          seat_overages.seats_available_for?(importable_root_ancestor, billable.map { |_, user| user.id },
            billable.first.first['access_level'], nil)
        end

        def enterprise_owner_import?
          importable_root_ancestor.is_a?(::Group) &&
            importable_root_ancestor.domain_verification_available? &&
            direct_root_owner?
        end

        # Group#has_owner? also counts Owners through group shares; only direct Owners qualify.
        def direct_root_owner?
          importable_root_ancestor.members.active_without_invites_and_requests.all_owners.with_user(@user).exists?
        end

        def enterprise_members(exported_members)
          emails = exported_members.filter_map { |member| get_email(member)&.downcase }.uniq
          return [] if emails.empty?

          # The members file has no row limit, so keep each IN list bounded.
          users = emails.each_slice(EMAIL_BATCH_SIZE).flat_map do |batch|
            importable_root_ancestor.enterprise_users
              .with_state(:active, :deactivated).non_internal.without_bots
              .by_user_email(batch)
              .select(:id, :email, :state)
              .to_a
          end
          users_by_email = users.index_by { |user| user.email.downcase }
          @enterprise_users_email_map = users.to_h { |user| [user.email, user.id] }

          exported_members.filter_map do |member|
            user = users_by_email[get_email(member)&.downcase]
            next unless user

            log_enterprise_member_mapping(member, user)

            [member.slice(*ENTERPRISE_MEMBER_KEYS)
              .merge('user' => member['user'].merge('public_email' => user.email)), user]
          end
        end

        def importable_root_ancestor
          @importable_root_ancestor ||= @importable.root_ancestor
        end

        def log_enterprise_member_mapping(member, user)
          logger.info(
            enterprise_log_params.merge(
              Labkit::Fields::LOG_MESSAGE => '[Project/Group Import] Mapped exported member to enterprise user',
              Labkit::Fields::GL_USER_ID => user.id,
              importing_user_id: @user.id,
              exported_user_id: Integer(member.dig('user', 'id'), exception: false)
            )
          )
        end

        def log_enterprise_mapping_summary(mapping_path, exported_count, mapped_count, without_membership_count)
          logger.info(
            enterprise_log_params.merge(
              Labkit::Fields::LOG_MESSAGE => '[Project/Group Import] Enterprise user mapping summary',
              Labkit::Fields::GL_USER_ID => @user.id,
              mapping_path: mapping_path,
              exported_members_count: exported_count,
              mapped_members_count: mapped_count,
              skipped_members_count: exported_count - mapped_count,
              mapped_without_membership_count: without_membership_count
            )
          )
        end

        def enterprise_log_params
          importable_id_field = @importable.is_a?(::Project) ? Labkit::Fields::GL_PROJECT_ID : Labkit::Fields::GL_NAMESPACE_ID

          {
            importable_id_field => @importable.id,
            Labkit::Fields::GL_ROOT_NAMESPACE_ID => importable_root_ancestor.id,
            importable_type: @importable.class.to_s
          }
        end
        # rubocop:enable Gitlab/ModuleWithInstanceVariables
      end
    end
  end
end
