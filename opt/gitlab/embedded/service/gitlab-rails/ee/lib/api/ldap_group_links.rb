# frozen_string_literal: true

module API
  class LdapGroupLinks < ::API::Base
    before { authenticate! }

    ldap_group_links_tags = %w[ldap]

    feature_category :user_management

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the group.'
    end
    resource :groups do
      desc 'List all LDAP group links' do
        detail 'Lists all LDAP group links.'
        success ::API::Entities::LdapGroupLink
        is_array true
        tags ldap_group_links_tags
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_ldap_group_link, boundary_type: :group
      get ":id/ldap_group_links" do
        group = find_group(params[:id])
        authorize! :read_ldap_group_link, group

        ldap_group_links = group.ldap_group_links

        if ldap_group_links.present?
          present ldap_group_links, with: ::API::Entities::LdapGroupLink
        else
          render_api_error!('No linked LDAP groups found', 404)
        end
      end

      desc 'Add an LDAP group link with CN or filter' do
        detail 'Adds an LDAP group link using a CN or filter.'
        success ::API::Entities::LdapGroupLink
        failure [
          { code: 400, message: 'Validation error' },
          { code: 404, message: 'Not found' },
          { code: 422, message: 'Unprocessable entity' }
        ]
        tags ldap_group_links_tags
      end
      params do
        optional 'cn', type: String, desc: 'CN of an LDAP group.'
        optional 'filter', type: String, desc: 'LDAP filter for the group.'
        requires 'group_access', type: Integer, values: Gitlab::Access.values_with_minimal_access,
          desc: 'Default access level for members of the LDAP group.'
        requires 'provider', type: String, desc: 'Name of the provider for the LDAP group link.'
        optional 'member_role_id', type: Integer, desc: 'ID of the member role for members of the LDAP group. ' \
                                                    'Ultimate only.'
        exactly_one_of :cn, :filter
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_ldap_group_link, boundary_type: :group
      post ":id/ldap_group_links" do
        group = find_group(params[:id])
        authorize! :create_ldap_group_link, group
        break not_found! if params[:filter] && !::License.feature_available?(:ldap_group_sync_filter)

        params.delete(:member_role_id) unless group.custom_roles_enabled?

        ldap_group_link = ::Members::CreateLdapGroupLinkService.execute(
          group: group, params: declared_params(include_missing: false), current_user: current_user
        )

        if ldap_group_link.persisted?
          present ldap_group_link, with: ::API::Entities::LdapGroupLink
        else
          render_api_error!(ldap_group_link.errors.full_messages.first, 409)
        end
      end

      desc 'Delete LDAP group link' do
        detail 'Deletes an LDAP group link. Deprecated. Scheduled for removal in a future release. Use ' \
          '`DELETE /groups/:id/ldap_group_links` instead.'
        success code: 204, message: 'Resource deleted'
        tags ldap_group_links_tags
      end
      params do
        requires :cn, type: String, desc: 'CN of an LDAP group.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :delete_ldap_group_link, boundary_type: :group
      # rubocop: disable CodeReuse/ActiveRecord
      delete ":id/ldap_group_links/:cn" do
        group = find_group(params[:id])
        authorize! :delete_ldap_group_link, group

        ldap_group_link = group.ldap_group_links.find_by(cn: params[:cn])

        if ldap_group_link
          ::Members::DestroyLdapGroupLinkService.execute(ldap_group_link, current_user: current_user)
          no_content!
        else
          render_api_error!('Linked LDAP group not found', 404)
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord

      desc 'Delete LDAP group link' do
        detail 'Deletes an LDAP group link for a specific LDAP provider. ' \
          'Deprecated. Scheduled for removal in a future release. Use `DELETE /groups/:id/ldap_group_links` instead.'
        success code: 204, message: 'Resource deleted'
        tags ldap_group_links_tags
      end
      params do
        requires :cn, type: String, desc: 'CN of an LDAP group.'
        requires :provider, type: String, desc: 'Name of the provider for the LDAP group link.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :delete_ldap_group_link, boundary_type: :group
      # rubocop: disable CodeReuse/ActiveRecord
      delete ":id/ldap_group_links/:provider/:cn" do
        group = find_group(params[:id])
        authorize! :delete_ldap_group_link, group

        ldap_group_link = group.ldap_group_links.find_by(cn: params[:cn], provider: params[:provider])

        if ldap_group_link
          ::Members::DestroyLdapGroupLinkService.execute(ldap_group_link, current_user: current_user)
          no_content!
        else
          render_api_error!('Linked LDAP group not found', 404)
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord

      desc 'Delete an LDAP group link with CN or filter' do
        detail 'Deletes an LDAP group link using a CN or filter.'
        success code: 204, message: 'Resource deleted'
        tags ldap_group_links_tags
      end
      params do
        optional 'cn', type: String, desc: 'CN of an LDAP group.'
        optional 'filter', type: String, desc: 'LDAP filter for the group.'
        requires 'provider', type: String, desc: 'Name of the provider for the LDAP group link.'
        exactly_one_of :cn, :filter
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :delete_ldap_group_link, boundary_type: :group
      # rubocop: disable CodeReuse/ActiveRecord
      delete ":id/ldap_group_links" do
        group = find_group(params[:id])
        authorize! :delete_ldap_group_link, group
        break not_found! if params[:filter] && !::License.feature_available?(:ldap_group_sync_filter)

        ldap_group_link = group.ldap_group_links.find_by(declared_params(include_missing: false))

        if ldap_group_link
          ::Members::DestroyLdapGroupLinkService.execute(ldap_group_link, current_user: current_user)
          no_content!
        else
          render_api_error!('Linked LDAP group not found', 404)
        end
      end
    end
  end
end
