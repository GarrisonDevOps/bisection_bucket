# frozen_string_literal: true

module API
  class Ldap < ::API::Base
    # Admin users by default should be able to access these API endpoints.
    # However, non-admin users can access these endpoints if the "Allow group
    # owners to manage LDAP-related group settings" is enabled, and they own a
    # group.
    before { authenticated_with_ldap_admin_access! }

    ldap_groups_tags = %w[ldap]
    feature_category :system_access

    resource :ldap do
      helpers do
        def get_group_list(provider, search)
          search = Net::LDAP::Filter.escape(search)
          Gitlab::Auth::Ldap::Adapter.new(provider).groups("#{search}*", 20)
        end

        params :search_params do
          optional :search, type: String, default: '', desc: 'Search for a specific LDAP group.'
        end
      end

      desc 'List all LDAP groups' do
        detail 'Lists all LDAP groups on the GitLab instance. Limited to 20 results.'
        success ::API::Entities::LdapGroup
        is_array true
        tags ldap_groups_tags
      end
      params do
        use :search_params
      end
      route_setting :authorization, permissions: :read_ldap_group, boundary_type: :instance
      get 'groups' do
        provider = Gitlab::Auth::Ldap::Config.available_servers.first['provider_name']
        groups = get_group_list(provider, params[:search])
        present groups, with: ::API::Entities::LdapGroup
      end

      desc 'List all LDAP groups by provider' do
        detail 'Lists all LDAP groups for the specified provider. Limited to 20 results.'
        success ::API::Entities::LdapGroup
        is_array true
        tags ldap_groups_tags
      end
      params do
        requires :provider, type: String, desc: 'Name of the LDAP provider.'
        use :search_params
      end
      route_setting :authorization, permissions: :read_ldap_group, boundary_type: :instance
      get ':provider/groups' do
        groups = get_group_list(params[:provider], params[:search])
        present groups, with: ::API::Entities::LdapGroup
      end
    end
  end
end
