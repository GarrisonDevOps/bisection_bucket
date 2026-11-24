# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    module BlockSeatOverages
      class << self
        def block_seat_overages?(source)
          root_namespace = source.root_ancestor
          return root_namespace.block_seat_overages? if gitlab_com_subscriptions?

          block_seat_overages_for_self_managed?
        end

        def seats_available_for?(source, invites, access_level, member_role_id)
          parsed_invites = process_invites(source, invites)

          if gitlab_com_subscriptions?
            return seats_available_for_group?(source.root_ancestor, parsed_invites, access_level, member_role_id)
          end

          seats_available_for_self_managed?(parsed_invites, access_level, member_role_id)
        end

        def seats_available_for_group?(root_group, invites, access_level, member_role_id)
          return true unless root_group.gitlab_subscription&.has_a_paid_hosted_plan?

          return true if saas_non_billable_member?(root_group, access_level, member_role_id)

          billable_ids = root_group.billed_user_ids[:user_ids].map(&:to_s)

          new_invites = invites.map(&:to_s) - billable_ids

          return true if new_invites.empty?

          root_group.gitlab_subscription.seats >= (billable_ids.count + new_invites.count)
        end

        def block_seat_overages_for_self_managed?
          ::Gitlab::CurrentSettings.seat_control_block_overages?
        end

        def seats_available_for_self_managed?(invites, access_level, member_role_id)
          return true if sm_non_billable_member?(access_level, member_role_id)

          billable_ids = get_billable_user_ids
          new_invites = invites - billable_ids
          return true if new_invites.empty?

          new_invites -= inactive_user_ids(new_invites)
          return true if new_invites.empty?

          ::License.current.seats >= (billable_ids.count + new_invites.count)
        end

        def non_billable_member?(source, access_level, member_role_id)
          if gitlab_com_subscriptions?
            return saas_non_billable_member?(source.root_ancestor, access_level, member_role_id)
          end

          sm_non_billable_member?(access_level, member_role_id)
        end

        def seat_upgrade_allowed?(user_id)
          return true if gitlab_com_subscriptions?
          return true unless block_seat_overages_for_self_managed?
          return true if bot_user?(user_id)
          return true if seats_available_for_self_managed?([user_id.to_s], Gitlab::Access::OWNER, nil)

          false
        end

        private

        def saas_non_billable_member?(root_namespace, access_level, member_role_id)
          if member_role_id
            custom_role = MemberRole.find_by_id(member_role_id)
            custom_role && !custom_role.occupies_seat?
          else
            access_level == ::Gitlab::Access::MINIMAL_ACCESS ||
              (access_level == ::Gitlab::Access::GUEST && root_namespace.exclude_guests?)
          end
        end

        def sm_non_billable_member?(access_level, member_role_id)
          if member_role_id
            custom_role = MemberRole.find_by_id(member_role_id)
            custom_role && !custom_role.occupies_seat?
          else
            access_level == ::Gitlab::Access::MINIMAL_ACCESS ||
              (access_level == ::Gitlab::Access::GUEST && ::License.current.exclude_guests_from_active_count?)
          end
        end

        def process_invites(source, list)
          emails, user_ids = parse_input_list(list)
          users = user_ids.present? ? User.id_in(user_ids) : []
          existing_users, non_existent_emails = process_emails(source, emails)

          all_users = (users + existing_users).uniq
          human_user_ids = human_users(all_users)

          human_user_ids + non_existent_emails
        end

        def parse_input_list(list)
          emails = []
          user_ids = []
          list.each do |item|
            case item
            when Integer
              user_ids << item
            when /\A\d+\Z/
              user_ids << item.to_i
            when Devise.email_regexp
              emails << item
            end
          end

          [emails, user_ids]
        end

        def process_emails(source, emails)
          case_insensitive_emails = emails.map(&:downcase).uniq
          return [[], []] if case_insensitive_emails.empty?

          users_by_emails = source.users_by_emails(case_insensitive_emails)
          existing_users = users_by_emails.values.compact
          non_existent_emails = case_insensitive_emails.select { |email| users_by_emails[email].nil? }

          [existing_users, non_existent_emails]
        end

        def human_users(users)
          human_users = users.select(&:human?)

          human_users.map { |user| user.id.to_s }
        end

        def get_billable_user_ids
          ::User.billable.select(:id).map { |user| user.id.to_s }
        end

        def inactive_user_ids(invites)
          _emails, user_ids = parse_input_list(invites)
          return [] if user_ids.empty?

          ::User.id_in(user_ids).without_active.pluck_primary_key.map(&:to_s)
        end

        def bot_user?(user_id)
          ::User.bots.id_in(user_id).exists?
        end

        def gitlab_com_subscriptions?
          ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        end
      end
    end
  end
end
