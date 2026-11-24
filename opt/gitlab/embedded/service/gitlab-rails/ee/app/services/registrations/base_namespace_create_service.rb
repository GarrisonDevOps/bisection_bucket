# frozen_string_literal: true

module Registrations
  class BaseNamespaceCreateService
    include BaseServiceUtility

    def initialize(user, group_params:)
      @user = user
      @group_params = group_params.dup
    end

    private

    attr_reader :user, :project, :group, :group_params

    def after_successful_group_creation(group_track_action:)
      ::Groups::CreateEventWorker.perform_async(group.id, user.id, 'created')
      ::Gitlab::Tracking.event(self.class.name, group_track_action, namespace: group, user: user)

      mark_group_for_duo_code_review_auto_enable

      apply_trial if onboarding_user_status.apply_trial?
    end

    def modified_group_params
      @group_params[:setup_for_company] = user.onboarding_status_setup_for_company

      return group_params unless group_needs_path_added?

      group_params
        .compact_blank
        .with_defaults(path: Namespace.clean_path(group_name))
    end

    def apply_trial
      trial_user_information = {
        namespace: group.slice(:id, :name, :path, :kind, :trial_ends_on),
        namespace_id: group.id,
        gitlab_com_trial: true,
        sync_to_gl: true,
        **glm_params
      }

      # deep_stringify_keys to ensure fully compliant with the worker's contract on the exact hash type.
      GitlabSubscriptions::Trials::ApplyTrialWorker.perform_async(user.id, trial_user_information.deep_stringify_keys)
    end

    def glm_params
      { glm_content: user.onboarding_status_glm_content, glm_source: user.onboarding_status_glm_source }.compact
    end

    def group_needs_path_added?
      group_name.present? && group_path.blank?
    end

    def group_name
      group_params[:name]
    end

    def group_path
      group_params[:path]
    end

    def onboarding_user_status
      @onboarding_user_status ||= ::Onboarding::UserStatus.new(user)
    end

    def mark_group_for_duo_code_review_auto_enable
      group.namespace_settings.enable_duo_code_review_by_default_pending!
    end
  end
end
