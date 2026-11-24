# frozen_string_literal: true

module SamlGroupLinksHelper
  def saml_group_link_input_names
    {
      base_access_level_input_name: "saml_group_link[access_level]",
      member_role_id_input_name: "saml_group_link[member_role_id]"
    }
  end

  # For SaaS only. Self-managed configures add-on groups in the configuration file.
  def duo_seat_assignment_available?(group)
    return false unless ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only)
    return false if group.has_parent?

    add_on_purchase = GitlabSubscriptions::Duo.enterprise_or_pro_for_namespace(group)
    return false unless add_on_purchase.present?

    add_on_purchase.active?
  end

  def multiple_saml_providers?
    saml_providers.count > 1
  end

  def saml_providers_for_dropdown
    saml_providers.map { |provider| [Gitlab::Auth::OAuth::Provider.label_for(provider), provider.to_s] }
  end

  def saml_restricted_access_warning_for_instance?
    ::Gitlab::CurrentSettings.seat_control_block_overages?
  end

  def saml_restricted_access_warning?(group)
    return saml_restricted_access_warning_for_instance? unless gitlab_com?

    group.root_ancestor.block_seat_overages?
  end

  def saml_restricted_access_warning
    ra_link = link_to('', help_page_path('subscriptions/manage_seats.md', anchor: 'restricted-access'))
    ra_learn_more = link_to('', help_page_path('subscriptions/manage_seats.md',
      anchor: 'provisioning-behavior-with-saml-scim-and-ldap'))

    safe_format(
      s_(
        'GroupSAML|With %{ra_link_start}restricted access%{ra_link_end} active and no seats available, ' \
          'new users provisioned through SAML/SCIM group sync are assigned the non-billable Minimal Access role. ' \
          'Learn more about %{ra_learn_more_start}provisioning behavior with SAML/SCIM%{ra_learn_more_end}.' \
      ),
      tag_pair(ra_link, :ra_link_start, :ra_link_end),
      tag_pair(ra_learn_more, :ra_learn_more_start, :ra_learn_more_end)
    )
  end

  private

  def gitlab_com?
    ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
  end
end
