# frozen_string_literal: true

module EE
  module Ci
    module DeployablePolicy
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        condition(:protected_environment) do
          @subject.persisted_environment.try(:protected_from?, @user)
        end

        rule { can?(:_update_protected_job) }.policy do
          enable :cancel_build
          enable(*all_job_update_abilities)
        end

        rule { ~can?(:_update_protected_job) & protected_environment }.policy do
          prevent(*all_job_write_abilities)
        end
      end

      private

      override :user_has_protected_environment_access?
      def user_has_protected_environment_access?
        subject.persisted_environment.try(:protected_by?, user)
      end
    end
  end
end
