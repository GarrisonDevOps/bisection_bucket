# frozen_string_literal: true

module Onboarding
  class TriggerAccountCreatedIterableService
    def initialize(user, status_presenter)
      @user = user
      @status_presenter = status_presenter
    end

    def execute
      return unless status_presenter.trigger_account_created_iterable?

      ::Onboarding::CreateIterableTriggerWorker.perform_async(iterable_params.stringify_keys)
    end

    private

    attr_reader :user, :status_presenter

    def iterable_params
      {
        provider: 'gitlab',
        work_email: user.email,
        uid: user.id,
        product_interaction: status_presenter.account_created_product_interaction,
        opt_in: user.onboarding_status_email_opt_in,
        preferred_language: ::Gitlab::I18n.trimmed_language_name(user.preferred_language),
        setup_for_company: user.onboarding_status_setup_for_company,
        role: user.onboarding_status_role_name,
        jtbd: user.onboarding_status_registration_objective_name,
        **glm_params
      }
    end

    def glm_params
      { glm_content: user.onboarding_status_glm_content, glm_source: user.onboarding_status_glm_source }.compact
    end
  end
end
