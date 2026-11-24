# frozen_string_literal: true

module EE
  module MergeRequests
    module ApprovalService
      extend ::Gitlab::Utils::Override
      # 5 seconds is chosen arbitrarily to ensure the user needs to just have re-authenticated to approve
      # Timeframe gives a short grace period for the callback from the identity provider to have processed.
      SAML_APPROVE_TIMEOUT = 5.seconds

      override :execute
      def execute(merge_request)
        # TODO: rename merge request approval setting to require_reauthentication_to_approve
        # Issue: https://gitlab.com/gitlab-org/gitlab/-/issues/431346
        #
        # use just the bare resolver here since this setting is for SAML and password now
        # we can't let this path go through the project require_password_to_approve
        return super unless mr_approval_setting_password_required?(merge_request)

        return super if current_user.duo_code_review_bot?

        require_saml_auth = approval_requires_saml_auth?

        if require_saml_auth && !saml_approval_in_time?
          return ServiceResponse.error(
            message: 'SAML authentication is required to approve',
            reason: :saml_reauthentication_required
          )
        end

        if incorrect_approval_password?(merge_request) && !require_saml_auth
          return ServiceResponse.error(
            message: 'Approval password is incorrect',
            reason: :incorrect_approval_password
          )
        end

        super
      end

      def approval_requires_saml_auth?
        return true if ::AuthHelper.group_saml_enabled? && group_requires_saml_auth?
        return true if instance_requires_saml_auth?

        false
      end

      private

      def incorrect_approval_password?(merge_request)
        merge_request.require_password_to_approve? &&
          !::Gitlab::Auth.find_with_user_password(current_user.username, params[:approval_password], activity: :web)
      end

      def instance_requires_saml_auth?
        ::Gitlab::Auth::Saml::SsoEnforcer
          .new(user: current_user, session_timeout: 0.seconds)
          .access_restricted?
      end

      def group_requires_saml_auth?
        ::Gitlab::Auth::GroupSaml::SsoEnforcer.access_restricted?(
          user: current_user,
          resource: project,
          session_timeout: 0.seconds
        )
      end

      def group
        project.group
      end

      def group_saml_provider
        group.root_saml_provider
      end

      def root_group
        group&.root_ancestor
      end

      def current_user_instance_saml_identities
        current_user.identities.with_provider(::AuthHelper.saml_providers)
      end

      def saml_approval_in_time?
        if group_saml_provider&.enabled?
          return ::Gitlab::Auth::GroupSaml::SsoState
            .new(group_saml_provider.id)
            .active_since?(SAML_APPROVE_TIMEOUT.ago)
        end

        current_user_instance_saml_identities.any? do |identity|
          ::Gitlab::Auth::Saml::SsoState
            .new(provider_id: identity.provider)
            .active_since?(SAML_APPROVE_TIMEOUT.ago)
        end
      end

      def mr_approval_setting_password_required?(merge_request)
        return true if merge_request.require_password_to_approve?
        return false unless root_group.is_a? Group

        ComplianceManagement::MergeRequestApprovalSettings::Resolver
          .new(root_group, project: merge_request.target_project)
          .require_password_to_approve
          .value
      end

      override :reset_approvals_cache
      def reset_approvals_cache(merge_request)
        merge_request.reset_approval_cache!
      end
    end
  end
end
