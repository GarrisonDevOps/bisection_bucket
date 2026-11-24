# frozen_string_literal: true

module AuthorizedProjectUpdate
  class ProjectRecalculatePerUserService < ProjectRecalculateService
    def initialize(project, user)
      @project = project
      @user = user
    end

    private

    attr_reader :user

    def shared_write_path?
      !::ProjectAuthorization.inside_transaction? && Feature.enabled?(:authz_refresh_write_path, user)
    end

    def write_through_shared_path
      return if Authz::ProjectAuthorizations::BlockedUserRefreshSkip
        .skip_and_log?(user, skipped_in: :project_recalculate)

      # Straight to the locked write: it recalculates and compares the one project under the user's lock, so an
      # unlocked comparison first would only add queries to every synchronous member change.
      written = Authz::ProjectAuthorizations::WriteBatchService.new(user_id: user.id).execute([project.id]) do |ids|
        ::ApplicationRecord.uncached do
          Authz::UserProjectGrants.new(user.id, cached: false).max_access_levels(ids)
        end
      end

      log_refresh(nil, written, shared_write_path: true)
    end

    def logged_user_id
      user.id
    end

    def apply_scopes(project_authorizations)
      super.where(user_id: user.id) # rubocop: disable CodeReuse/ActiveRecord
    end

    def effective_access_levels
      Projects::Members::EffectiveAccessLevelPerUserFinder.new(project, user).execute
    end
  end
end
