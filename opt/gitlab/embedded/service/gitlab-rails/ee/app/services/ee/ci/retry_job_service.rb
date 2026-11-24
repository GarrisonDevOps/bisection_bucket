# frozen_string_literal: true

module EE
  module Ci
    module RetryJobService
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      private

      override :check_access!
      def check_access!(build, variables: [])
        super

        begin
          ::Users::IdentityVerification::AuthorizeCi.new(user: current_user, project: project).authorize_run_jobs!
        rescue ::Users::IdentityVerification::Error => e
          raise ::Gitlab::Access::AccessDeniedError, e
        end
      end

      override :check_assignable_runners!
      def check_assignable_runners!(build)
        result = runners_availability_checker.check(build.build_matcher)
        build.drop!(result.drop_reason) unless result.available?
      end

      def runners_availability_checker
        ::Gitlab::Ci::RunnersAvailabilityChecker.instance_for(project)
      end
    end
  end
end
