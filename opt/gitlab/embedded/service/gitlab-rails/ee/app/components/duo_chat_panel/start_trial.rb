# frozen_string_literal: true

module DuoChatPanel
  module StartTrial
    include DuoChatPanel::PanelCommon

    private

    def can_start_trial?(user, source: nil)
      trial_path(user, source: source).present?
    end

    def trial_path(user, source: nil)
      return if skip_trial_experience?

      if saas?
        saas_trial_path(source: source)
      elsif Ability.allowed?(user, :update_gitlab_subscription)
        ::Gitlab::Routing.url_helpers.new_self_managed_trials_path
      end
    end

    def saas_trial_path(source: nil)
      if source.nil? || source.root_ancestor.is_a?(::Namespaces::UserNamespace)
        ::Gitlab::Routing.url_helpers.new_trial_path(glm_source: 'gitlab.com', glm_content: 'chat panel')
      elsif user_can_start_trial_in_source?(source)
        ::Gitlab::Routing.url_helpers.new_trial_path(
          namespace_id: source.root_ancestor.id, glm_source: 'gitlab.com', glm_content: 'chat panel'
        )
      end
    end

    def user_can_start_trial_in_source?(source)
      root = source.root_ancestor

      root&.persisted? && root.has_free_or_no_subscription? &&
        Ability.allowed?(user, :start_trial, root)
    end

    # Dedicated customers are already on Ultimate, so they are never trial eligible.
    def skip_trial_experience?
      ::Gitlab::Dedicated.feature_available?(:skip_ultimate_trial_experience)
    end
  end
end
