# frozen_string_literal: true

module EE
  module Ci
    module PlayBuildService
      extend ::Gitlab::Utils::Override

      private

      override :check_access!
      def check_access!
        super

        begin
          ::Users::IdentityVerification::AuthorizeCi.new(user: current_user, project: project).authorize_run_jobs!
        rescue ::Users::IdentityVerification::Error => e
          raise ::Gitlab::Access::AccessDeniedError, e
        end
      end
    end
  end
end
