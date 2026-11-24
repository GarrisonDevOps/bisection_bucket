# frozen_string_literal: true

module Security
  module OrganizationPolicySetting
    extend ActiveSupport::Concern
    include ::Gitlab::Utils::StrongMemoize

    private

    def organization_policy_setting
      ::Security::PolicySetting.in_organization(organization)
    end
    strong_memoize_attr :organization_policy_setting

    def csp_enabled?
      !!organization_policy_setting&.csp_enabled?
    end
  end
end
