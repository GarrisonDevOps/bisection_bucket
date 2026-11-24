# frozen_string_literal: true

module EE
  module SamlProvidersHelper
    def saml_link_for_provider(text, provider, **args)
      saml_button(text, provider.group.full_path, **args)
    end

    def saml_button(text, group_path, redirect: nil, variant: :default, block: false, **button_options)
      url = saml_url(group_path, redirect)
      render Pajamas::ButtonComponent.new(
        href: url,
        method: :post,
        variant: variant,
        block: block,
        button_options: button_options) do
        text
      end
    end

    def saml_link(text, group_path, redirect: nil, html_class: '', id: nil, data: nil)
      url = saml_url(group_path, redirect)
      link_to(text, url, method: :post, class: html_class, id: id, data: data)
    end

    def group_saml_sign_in(group:, group_name:, group_path:, redirect:, sign_in_button_text:)
      {
        group_name: group_name,
        group_url: group_path(group),
        rememberable: Devise.mappings[:user].rememberable?.to_s,
        saml_url: saml_url(group_path, redirect),
        sign_in_button_text: sign_in_button_text
      }
    end

    def saml_membership_role_selector_data(group, current_user)
      data = {
        standard_roles: group.access_level_roles,
        current_standard_role: group.saml_provider.default_membership_role
      }

      if group.custom_roles_enabled?
        custom_roles = MemberRoles::RolesFinder.new(current_user, { parent: group })
          .execute.map do |role|
            { member_role_id: role.id, name: role.name, base_access_level: role.base_access_level }
          end

        data.merge!(
          custom_roles: custom_roles,
          current_custom_role_id: group.saml_provider.member_role_id
        )
      end

      data
    end

    def saml_reload_data(provider)
      {
        saml_provider_id: provider.id,
        saml_sessions_url: saml_user_settings_active_sessions_path(format: :json)
      }
    end

    private

    def saml_url(group_path, redirect = nil)
      redirect ||= group_path(group_path)

      omniauth_authorize_path(:user, :group_saml, group_path: group_path, redirect_to: redirect)
    end
  end
end
