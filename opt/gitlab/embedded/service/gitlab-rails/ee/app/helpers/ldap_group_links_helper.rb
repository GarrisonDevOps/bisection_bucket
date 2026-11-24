# frozen_string_literal: true

module LdapGroupLinksHelper
  def ldap_group_link_input_names
    {
      base_access_level_input_name: "ldap_group_link[group_access]",
      member_role_id_input_name: "ldap_group_link[member_role_id]"
    }
  end

  def ldap_restricted_access_warning?
    ::Gitlab::CurrentSettings.seat_control_block_overages?
  end

  def ldap_restricted_access_warning
    ra_link = link_to('', help_page_path('subscriptions/manage_seats.md',
      anchor: 'restricted-access')
    )
    ra_learn_more = link_to('',
      help_page_path('subscriptions/manage_seats.md',
        anchor: 'provisioning-behavior-with-saml-scim-and-ldap')
    )

    safe_format(
      s_(
        'LDAP|With %{ra_link_start}restricted access%{ra_link_end} active and no seats available, ' \
          'new users provisioned through LDAP sync are assigned the non-billable Minimal Access role. ' \
          'Learn more about %{ra_learn_more_start}provisioning behavior with LDAP%{ra_learn_more_end}.'
      ),
      tag_pair(ra_link, :ra_link_start, :ra_link_end),
      tag_pair(ra_learn_more, :ra_learn_more_start, :ra_learn_more_end)
    )
  end
end
