# frozen_string_literal: true

class Groups::LdapGroupLinksController < Groups::ApplicationController
  before_action :require_ldap_enabled
  before_action :authorize_read_ldap_group_link!, only: :index
  before_action :authorize_create_ldap_group_link!, only: :create
  before_action :authorize_delete_ldap_group_link!, only: :destroy
  before_action :set_hide_search_settings, only: [:index]

  layout 'group_settings'

  feature_category :user_management

  def index; end

  def create
    ldap_group_link = Members::CreateLdapGroupLinkService.execute(
      group: @group, params: ldap_group_link_params, current_user: current_user
    )

    if ldap_group_link.persisted?
      if request.referer && request.referer.include?('admin')
        redirect_to [:admin, @group], notice: 'New LDAP link saved'
      else
        redirect_back_or_default(default: { action: 'index' }, options: { notice: 'New LDAP link saved' })
      end
    else
      redirect_back_or_default(
        default: { action: 'index' },
        options: { alert: "Could not create new LDAP link: #{ldap_group_link.errors.full_messages * ', '}" }
      )
    end
  end

  def destroy
    ldap_group_link = @group.ldap_group_links.find_by_id(params.permit(:id)[:id])

    Members::DestroyLdapGroupLinkService.execute(ldap_group_link, current_user: current_user) if ldap_group_link

    redirect_back_or_default(default: { action: 'index' }, options: { notice: 'LDAP link removed' })
  end

  private

  def set_hide_search_settings
    @hide_search_settings = true
  end

  def authorize_read_ldap_group_link!
    render_404 unless can?(current_user, :read_ldap_group_link, group)
  end

  def authorize_create_ldap_group_link!
    render_404 unless can?(current_user, :create_ldap_group_link, group)
  end

  def authorize_delete_ldap_group_link!
    render_404 unless can?(current_user, :delete_ldap_group_link, group)
  end

  def require_ldap_enabled
    render_404 unless Gitlab.config.ldap.enabled
  end

  def ldap_group_link_params
    attrs = %i[cn group_access provider]
    attrs << :filter if ::License.feature_available?(:ldap_group_sync_filter)
    attrs << :member_role_id if group.custom_roles_enabled?

    params.require(:ldap_group_link).permit(attrs)
  end
end
