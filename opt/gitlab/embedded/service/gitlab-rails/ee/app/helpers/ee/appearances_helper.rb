# frozen_string_literal: true

module EE
  module AppearancesHelper
    extend ::Gitlab::Utils::Override

    override :default_brand_title
    def default_brand_title
      _('GitLab Enterprise Edition')
    end

    override :custom_sign_in_brand_title
    def custom_sign_in_brand_title
      return unless ::Onboarding.enabled?

      _("Sign in to GitLab")
    end

    override :custom_sign_up_brand_title
    def custom_sign_up_brand_title
      return unless ::Onboarding.enabled?

      _("Get started with GitLab")
    end
  end
end
