# frozen_string_literal: true

module EE
  module ProjectCiCdSetting
    extend ActiveSupport::Concern

    prepended do
      enum :restrict_pipeline_cancellation_role, {
        developer: 0,
        maintainer: 1,
        no_one: 2
      }, prefix: true
    end

    def merge_pipelines_enabled?
      project.feature_available?(:merge_pipelines) && super
    end

    def merge_trains_enabled?
      super &&
        merge_pipelines_enabled? &&
        project.feature_available?(:merge_trains)
    end

    def merge_pipelines_were_disabled?
      saved_change_to_attribute?(:merge_pipelines_enabled, from: true, to: false)
    end

    def auto_rollback_enabled?
      super && project.feature_available?(:auto_rollback)
    end

    def merge_trains_skip_train_allowed?
      merge_trains_skip_train_allowed &&
        merge_trains_enabled? &&
        !project.ff_merge_must_be_possible? && # Not yet supported, see https://gitlab.com/gitlab-org/gitlab/-/issues/429009
        ::Feature.enabled?(:merge_trains_skip_train, project)
    end

    # Whether the given user is required to go through the merge train and
    # cannot merge directly (UI "Merge immediately" / REST `/merge`).
    def merge_train_enforced_for?(user)
      return false unless merge_trains_enabled?
      return false if merge_train_enforcement_allow_bypass?

      if merge_train_enforcement_enforce_with_owner_override? && user
        # Owners and administrators keep the ability to bypass the train.
        return false if user.can_admin_all_resources?
        return false if project.team.member?(user, ::Gitlab::Access::OWNER)
      end

      true
    end
  end
end
