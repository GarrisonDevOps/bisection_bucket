# frozen_string_literal: true

module GitlabSubscriptions
  module CartAbandonmentConcern
    extend ActiveSupport::Concern

    included do
      urgency :low
      feature_category :acquisition
      defer_on_database_health_signal :gitlab_main, [:users, :namespaces], 2.minutes
      deduplicate :until_executing, including_scheduled: true
    end

    private

    def find_user_and_namespace(user_id, namespace_id)
      [User.find_by_id(user_id), Namespace.find_by_id(namespace_id)]
    end

    def send_cart_abandonment_lead(user, params)
      GitlabSubscriptions::CreateHandRaiseLeadService.new(user: user).execute(params)
    end

    def build_base_lead_params(user, namespace)
      {
        work_email: user.email,
        opt_in: user.onboarding_status_email_opt_in,
        namespace_id: namespace.id,
        existing_plan: namespace.actual_plan_name,
        skip_country_validation: true
      }.tap do |params|
        params[:role] = user.onboarding_status_role_name if user.onboarding_status_role_name.present?
        if user.preferred_language.present?
          params[:preferred_language] =
            ::Gitlab::I18n.trimmed_language_name(user.preferred_language)
        end
      end
    end
  end
end
