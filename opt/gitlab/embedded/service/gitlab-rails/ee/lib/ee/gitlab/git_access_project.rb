# frozen_string_literal: true

module EE
  module Gitlab
    module GitAccessProject
      extend ::Gitlab::Utils::Override

      EE_ERROR_MESSAGES = {
        namespace_forbidden: 'You are not allowed to access projects in this namespace.'
      }.freeze

      private

      override :check_download_access!
      def check_download_access!
        result = ::Users::Abuse::ProjectsDownloadBanCheckService.execute(user, project)
        raise ::Gitlab::GitAccess::ForbiddenError, download_forbidden_message if result.error?

        super
      end

      override :check_namespace!
      def check_namespace!
        unless allowed_access_namespace?
          raise ::Gitlab::GitAccess::ForbiddenError, EE_ERROR_MESSAGES[:namespace_forbidden]
        end

        super
      end

      def allowed_access_namespace?
        # Verify namespace access only on initial call from Gitlab Shell and Workhorse
        return true unless changes == ::Gitlab::GitAccess::ANY

        # Return early if ssh certificate feature is not enabled for namespace
        # If allowed_namespace_path is passed anyway, we return false
        # It may happen, when a user authenticates via SSH certificate and tries accessing to personal namespace
        return allowed_namespace_path.blank? unless namespace&.licensed_feature_available?(:ssh_certificates)

        # When allowed_namespace_path is not specified, it's checked whether SSH certificates are enforced
        return !enforced_ssh_certificates? if allowed_namespace_path.blank?

        allowed_namespace = ::Namespace.find_by_full_path(allowed_namespace_path)
        allowed_namespace.present? && namespace.root_ancestor.id == allowed_namespace.id
      end

      # Verify that enabled_git_access_protocol is ssh_certificates and the
      # actor is either User or Key
      # Deploy keys are allowed anyway
      def enforced_ssh_certificates?
        return false unless namespace.root_ancestor.enforce_ssh_certificates?
        return false unless actor.is_a?(User) || actor.instance_of?(::Key)
        return false if request_from_ci_build?

        user.human?
      end
    end
  end
end
