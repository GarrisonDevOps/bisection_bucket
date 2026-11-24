# frozen_string_literal: true

module EE
  module AuthHelper
    extend ::Gitlab::Utils::Override

    PROVIDERS_WITH_ICONS = %w[
      kerberos
    ].freeze
    GROUP_LEVEL_PROVIDERS = %i[group_saml].freeze

    override :display_providers_on_profile?
    def display_providers_on_profile?
      super || group_saml_enabled?
    end

    override :button_based_providers
    def button_based_providers
      super - GROUP_LEVEL_PROVIDERS
    end

    override :providers_for_base_controller
    def providers_for_base_controller
      super - GROUP_LEVEL_PROVIDERS
    end

    override :provider_has_builtin_icon?
    def provider_has_builtin_icon?(name)
      super || PROVIDERS_WITH_ICONS.include?(name.to_s)
    end

    override :form_based_provider_priority
    def form_based_provider_priority
      super << 'smartcard'
    end

    override :form_based_providers
    def form_based_providers
      providers = super

      providers << :smartcard if smartcard_enabled?

      providers
    end

    def password_rule_list(basic)
      if ::License.feature_available?(:password_complexity)
        rules = []
        rules.concat([:length, :common, :user_info]) if basic
        rules << :number if ::Gitlab::CurrentSettings.password_number_required?
        rules << :lowercase if ::Gitlab::CurrentSettings.password_lowercase_required?
        rules << :uppercase if ::Gitlab::CurrentSettings.password_uppercase_required?
        rules << :symbol if ::Gitlab::CurrentSettings.password_symbol_required?

        rules
      end
    end

    def google_tag_manager_enabled?
      return false unless ::Gitlab::Saas.feature_available?(:marketing_google_tag_manager)

      extra_config.has_key?('google_tag_manager_nonce_id') &&
        extra_config.google_tag_manager_nonce_id.present?
    end

    def google_tag_manager_id
      return unless google_tag_manager_enabled?

      extra_config.google_tag_manager_nonce_id
    end

    def kerberos_enabled?
      auth_providers.include?(:kerberos)
    end

    def smartcard_enabled?
      ::Gitlab::Auth::Smartcard.enabled?
    end

    def smartcard_enabled_for_ldap?(provider_name, required: false)
      return false unless smartcard_enabled?

      server = ::Gitlab::Auth::Ldap::Config.servers.find do |server|
        server['provider_name'] == provider_name
      end

      return false unless server

      truthy_values = ['required']
      truthy_values << 'optional' unless required

      truthy_values.include? server['smartcard_auth']
    end

    def smartcard_login_button_category(provider_name)
      return :secondary unless smartcard_enabled_for_ldap?(provider_name, required: true)

      :primary
    end

    def group_saml_enabled?
      auth_providers.include?(:group_saml)
    end

    def saml_group_sync_enabled?
      return true if group_saml_enabled?

      saml_providers.any? do |provider|
        ::Gitlab::Auth::Saml::Config.new(provider).group_sync_enabled?
      end
    end

    override :admin_sa_token_expiry_enforced?
    def admin_sa_token_expiry_enforced?
      ::Gitlab::CurrentSettings.current_application_settings.service_access_tokens_expiration_enforced
    end

    override :group_sa_token_expiry_enforced?
    def group_sa_token_expiry_enforced?(group)
      group.namespace_settings.service_access_tokens_expiration_enforced
    end

    override :project_sa_token_expiry_enforced?
    def project_sa_token_expiry_enforced?(project)
      project.root_namespace.namespace_settings.service_access_tokens_expiration_enforced
    end
  end
end
