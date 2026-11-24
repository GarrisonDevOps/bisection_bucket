# frozen_string_literal: true

module EE
  module OmniauthCallbacksController
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      include ::Gitlab::RackLoadBalancingHelpers
      include ::Users::IdentityVerificationHelper
    end

    override :openid_connect
    def openid_connect
      if License.feature_available?(:oidc_client_groups_claim)
        omniauth_flow(::Gitlab::Auth::Oidc)
      else
        super
      end
    end

    private

    override :log_failed_login
    def log_failed_login(user_or_login, provider)
      ::Authn::UnauthenticatedSecurityEventAuditor.new(
        user_or_login,
        provider.upcase,
        event_name: 'omniauth_login_failed',
        message: "#{provider.upcase} login failed"
      ).execute
    end

    override :perform_registration_tasks
    def perform_registration_tasks(user, provider)
      # This also protects the sub classes group saml and ldap from staring onboarding
      # as we don't want those to onboard.
      if provider.to_sym.in?(::AuthHelper.providers_for_base_controller)
        ::Onboarding::StatusCreateService
          .new(
            request.env.fetch('omniauth.params', {}).deep_symbolize_keys,
            session['user_return_to'],
            user,
            onboarding_first_step_path
          ).execute
        clear_memoization(:onboarding_status_presenter) # clear since registration_type is now set

        # We need to do this here since the subscription flow relies on what was set
        # in the stored_location_for(:user) that was set on initial redirect from
        # the ::GitlabSubscriptions::SubscriptionsController#new and super will wipe that out.
        # Then the RegistrationsIdentityVerificationController#success will get
        # whatever is set in super instead of the subscription path we desire.
        super unless onboarding_status_presenter.preserve_stored_location?

        @new_user = true
      else
        super
      end
    end

    override :after_sign_in_path_for
    def after_sign_in_path_for(user)
      # For new customers-portal-bound registrations, resolve the interstitial directly:
      # normal resolution would consume stored_location_for(:user), which must keep the
      # CDot URL intact for CustomersPortalRedirectController. The @new_user guard keeps
      # ordinary SSO sign-ins of existing users on the normal stored-location flow.
      if @new_user && onboarding_status_presenter.redirect_to_customers_portal?
        after_sign_up_path
      else
        super
      end
    end

    override :sign_in_and_redirect_or_verify_identity
    def sign_in_and_redirect_or_verify_identity(user, auth_user, new_user)
      return super if user.blocked? # When `block_auto_created_users` is set to true
      return super unless auth_user.signup_identity_verification_enabled?(user)
      return super if !new_user && user.signup_identity_verified?

      service_class = ::Users::EmailVerification::SendCustomConfirmationInstructionsService
      service_class.new(user).execute if new_user
      session[:verification_user_id] = user.id
      load_balancer_stick_request(::User, :user, user.id)

      redirect_to signup_identity_verification_path
    end

    override :build_auth_user_params
    def build_auth_user_params
      omniauth_params = request.env.fetch('omniauth.params', {}).deep_symbolize_keys

      # This protects the sub classes group saml and ldap from adding this param. If the builder class inheritance
      # were a bit more declarative and had a base class, we could probably be a bit more declarative here and skip
      # the provider check.
      # The opt_in check may get removed in https://gitlab.com/gitlab-org/gitlab/-/merge_requests/164411.
      unless ::Onboarding.enabled? && oauth['provider'].to_sym.in?(::AuthHelper.providers_for_base_controller) &&
          omniauth_params.key?(:onboarding_status_email_opt_in)
        return super
      end

      data = super
      # We want to say that if for some reason the param is nil or not present, then we can't
      # be certain the user was ever shown this option so we should default to false to follow opt in guidelines.
      opt_in = request.env.fetch('omniauth.params', {}).deep_symbolize_keys[:onboarding_status_email_opt_in]
      data[:onboarding_status_email_opt_in] = ::Gitlab::Utils.to_boolean(opt_in, default: false)
      data
    end

    override :allowed_new_user?
    def allowed_new_user?(auth_user)
      # We need to stop new sign ups in case of restricted countries based on the user IP address
      # It should only apply for new signups, so we check if the user is new in the database.
      new_user = super

      if new_user && pipl_restricted_country?(request.env['HTTP_CF_IPCOUNTRY'])

        return new_user if allow_invited_user?

        # This logger statement can be deleted while we are deleting feature flag
        ::Gitlab::AppLogger.info("Gitlab Signup via SSO failed for Region: #{request.env['HTTP_CF_IPCOUNTRY']}")

        raise ::OmniauthCallbacksController::SignUpFromRestrictedCountyError
      end

      new_user
    end

    # SAML and OIDC can grant admin access through IdP groups (`admin_groups`). Persists the recomputed admin,
    # auditor and external flags (and the SAML required-group block), but not the sign-in-only group membership
    # and Duo seat sync.
    override :admin_access_after_sync?
    def admin_access_after_sync?(auth_user)
      return super unless sync_user_on_admin_mode_entry?(auth_user)

      auth_user.save
      # As on sign-in, refuse when the save failed: a failed `system_block` leaves `gl_user` active in memory.
      return false unless auth_user.valid_sign_in?

      user = auth_user.gl_user
      user.active? && user.can_access_admin_area?
    rescue ::Gitlab::Auth::OAuth::User::SigninDisabledForProviderError,
      ::Gitlab::Auth::OAuth::User::SignupDisabledError
      # OIDC raises SignupDisabledError for a user outside `required_groups`. As on sign-in, nothing is
      # persisted, so the admin flag is kept and only this entry is refused.
      false
    end

    def sync_user_on_admin_mode_entry?(auth_user)
      ::AuthHelper.saml_providers.include?(oauth['provider'].to_sym) || auth_user.is_a?(::Gitlab::Auth::Oidc::User)
    end

    override :set_session_active_since
    def set_session_active_since(id)
      ::Gitlab::Auth::Saml::SsoState.new(provider_id: id)
        .update_active(session_not_on_or_after: session_not_on_or_after_attribute)
    end

    override :store_redirect_to
    def store_redirect_to
      redirect_to = request.env.dig('omniauth.params', 'redirect_to').presence
      redirect_to = sanitize_redirect redirect_to

      return unless redirect_to
      return unless valid_gitlab_initiated_saml_request?

      store_location_for :redirect, redirect_to
    end

    def saml_response
      oauth.fetch(:extra, {}).fetch(:response_object, {})
    end

    def session_not_on_or_after_attribute
      return unless saml_response.present? # response object can be nil in case authentication fails

      saml_response.session_expires_at
    end

    def valid_gitlab_initiated_saml_request?
      ::Gitlab::Auth::Saml::OriginValidator.new(session).gitlab_initiated?(saml_response)
    end

    def allow_invited_user?
      member_id = session[:originating_member_id]
      return unless member_id

      member = ::Member.find_by_id(member_id)

      invite_root_namespace = member&.source&.root_ancestor

      return false unless invite_root_namespace

      invite_root_namespace.paid? || invite_root_namespace.trial?
    end
  end
end
