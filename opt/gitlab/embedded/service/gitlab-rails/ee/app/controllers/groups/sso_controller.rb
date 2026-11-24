# frozen_string_literal: true

class Groups::SsoController < Groups::ApplicationController
  include InternalRedirect
  include OneTrustCSP

  skip_before_action :group

  # TODO: Assess how step-up auth should be enforced in the SSO context, then implement
  # See: https://gitlab.com/gitlab-org/gitlab/-/issues/578868
  # This controller uses `unauthenticated_group` instead of `@group` to support SSO flows
  # for unauthenticated users. Parent's enforcement expects @group, causing RecordNotFound.
  skip_before_action :enforce_step_up_auth_for_namespace

  before_action :init_preferred_language
  before_action :authenticate_user!, only: [:unlink]
  before_action :require_group_saml_instance!
  before_action :require_licensed_group!, except: [:unlink]
  before_action :require_saml_provider!
  before_action :require_enabled_provider!, except: [:unlink]
  before_action :check_user_can_sign_in_with_provider, only: [:saml]
  before_action :group, only: [:saml]
  before_action :redirect_if_group_moved

  layout 'devise'

  feature_category :system_access
  urgency :low

  def saml
    session_redirect = session.delete(:user_sso_return_to)

    @redirect_path = session_redirect || safe_redirect_path(permitted_params[:redirect]) ||
      group_path(unauthenticated_group)
    @group_path = unauthenticated_group.path
    @group_name = unauthenticated_group.full_name
    @group_saml_identity = linked_identity
    @auto_redirect_to_provider = current_user&.group_sso?(unauthenticated_group)

    render layout: 'devise_empty' if @auto_redirect_to_provider
  end

  def unlink
    return route_not_found unless linked_identity

    GroupSaml::Identity::DestroyService.new(linked_identity).execute

    redirect_to profile_two_factor_auth_path
  end

  private

  def permitted_params
    params.permit(:group_id, :redirect, :token)
  end

  def group
    @group ||= unauthenticated_group
  end

  def linked_identity
    @linked_identity ||= GroupSamlIdentityFinder.new(user: current_user).find_linked(group: unauthenticated_group)
  end

  def unauthenticated_group
    @unauthenticated_group ||= Group.find_by_full_path(permitted_params[:group_id], follow_redirects: true)
  end

  def require_group_saml_instance!
    route_not_found unless Gitlab::Auth::GroupSaml::Config.enabled?
  end

  def require_licensed_group!
    route_not_found unless unauthenticated_group&.feature_available?(:group_saml)
  end

  def require_saml_provider!
    redirect_settings_or_not_found unless unauthenticated_group.saml_provider
  end

  def require_enabled_provider!
    redirect_settings_or_not_found unless unauthenticated_group.saml_provider&.enabled?
  end

  def redirect_settings_or_not_found
    if can?(current_user, :admin_group_saml, unauthenticated_group)
      flash[:notice] = 'SAML sign on has not been configured for this group'
      redirect_to [@unauthenticated_group, :saml_providers]
    else
      route_not_found
    end
  end

  def check_user_can_sign_in_with_provider
    actor = saml_discovery_token_actor || current_user
    route_not_found unless can?(actor, :sign_in_with_saml_provider, unauthenticated_group.saml_provider)
  end

  def saml_discovery_token_actor
    token = permitted_params[:token]
    Gitlab::Auth::GroupSaml::TokenActor.new(token) if token
  end

  def redirect_if_group_moved
    ensure_canonical_path(unauthenticated_group, permitted_params[:group_id])
  end
end
