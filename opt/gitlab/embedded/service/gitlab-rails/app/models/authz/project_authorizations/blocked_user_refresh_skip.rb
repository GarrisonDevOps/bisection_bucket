# frozen_string_literal: true

module Authz
  module ProjectAuthorizations
    # Decides whose project_authorizations refreshes are skipped because the user is blocked.
    #
    # Blocked humans cannot sign in or use tokens, so their rows are left as they are until the
    # user becomes active again, when the User state machine schedules a full refresh.
    class BlockedUserRefreshSkip
      BATCH_SIZE = 1_000

      class << self
        # Whether refreshes of the user's authorizations are skipped, and logs the refresh as skipped
        # when it is.
        #
        # @param user [User]
        # @param skipped_in [Symbol] the code path that skips it, one of :user_refresh,
        #   :project_recalculate or :safety_net_check
        # @return [Boolean]
        def skip_and_log?(user, skipped_in:)
          return false unless applies_to?(user)

          log_skipped([user.id], skipped_in: skipped_in)

          true
        end

        # Returns the users whose rows a refresh leaves as they are, and logs them as skipped.
        #
        # @param user_ids [Array<Integer>]
        # @param skipped_in [Symbol] the code path that skips them, one of :user_refresh,
        #   :project_recalculate or :safety_net_check
        # @return [Set<Integer>]
        def skipped_user_ids(user_ids, skipped_in:)
          # Checked before the lookup so that a disabled flag costs no query.
          enabled_user_ids = user_ids.uniq.select { |user_id| enabled_for?(::User.actor_from_id(user_id)) }

          skipped = enabled_user_ids.each_slice(BATCH_SIZE).flat_map do |batch|
            ::User.id_in(batch).human.with_states(*::User::BLOCKED_STATES).select(:id).preload(:custom_attributes)
              .reject { |user| deletion_started?(user) }
              .map(&:id)
          end.to_set

          log_skipped(skipped, skipped_in: skipped_in) if skipped.any?

          skipped
        end

        # Like {.skipped_user_ids}, for users that are already loaded: the state is read from them
        # and the deletion marks are looked up once for all of them.
        #
        # @param users [Array<User>]
        # @param skipped_in [Symbol] the code path that skips them, one of :user_refresh,
        #   :project_recalculate or :safety_net_check
        # @return [Set<Integer>]
        def skipped_user_ids_among(users, skipped_in:)
          blocked_user_ids = users.select { |user| blocked_human?(user) && enabled_for?(user) }.map(&:id)

          skipped_and_logged(blocked_user_ids, skipped_in: skipped_in)
        end

        private

        def applies_to?(user)
          blocked_human?(user) && enabled_for?(user) && !deletion_started?(user)
        end

        # Logs the users skipped by one refresh in a single line, so a caller that skips many users
        # at once does not write a line per user.
        def log_skipped(user_ids, skipped_in:)
          Gitlab::AppJsonLogger.info(
            event: 'authorized_projects_refresh_skipped',
            'authorized_projects_refresh.skip_reason': 'user_blocked',
            'authorized_projects_refresh.skipped_in': skipped_in.to_s,
            'authorized_projects_refresh.skipped_users_count': user_ids.size
          )
        end

        def blocked_human?(user)
          user.human? && user.blocked?
        end

        # A skipped row for a removed membership still grants access after an unblock, until the
        # refresh on activation runs, unless access is resolved from memberships.
        def enabled_for?(actor)
          Feature.enabled?(:skip_authorization_refresh_for_blocked_users, actor) &&
            Feature.enabled?(:resolve_project_access_from_memberships, actor)
        end

        def skipped_and_logged(blocked_user_ids, skipped_in:)
          skipped = blocked_user_ids.each_slice(BATCH_SIZE).flat_map do |batch|
            batch - deletion_started_user_ids(batch)
          end.to_set

          log_skipped(skipped, skipped_in: skipped_in) if skipped.any?

          skipped
        end

        # Reads the attributes in memory when the caller preloaded them, so a batch of users costs one query.
        def deletion_started?(user)
          if user.custom_attributes.loaded?
            user.custom_attributes.any? { |attribute| attribute.key == ::UserCustomAttribute::DELETION_STARTED_AT }
          else
            deletion_started_attributes.by_user_id(user.id).exists?
          end
        end

        def deletion_started_user_ids(user_ids)
          deletion_started_attributes.by_user_id(user_ids).pluck(:user_id) # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- bounded by the batch
        end

        def deletion_started_attributes
          ::UserCustomAttribute.by_key(::UserCustomAttribute::DELETION_STARTED_AT)
        end
      end
    end
  end
end
