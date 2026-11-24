# frozen_string_literal: true

module EE
  module Namespaces
    module UserNamespacePolicy
      extend ActiveSupport::Concern

      prepended do
        condition(:read_only, scope: :subject) { @subject.read_only? }
        condition(:compliance_framework_available, scope: :subject) do
          @subject.licensed_feature_available?(:custom_compliance_frameworks)
        end

        rule { admin & is_gitlab_com }.enable :update_subscription_limit

        rule { owner | admin }.policy do
          enable :read_billable_member
          enable :read_compute_minutes
          enable :admin_compliance_framework
        end

        rule { ~compliance_framework_available }.prevent :admin_compliance_framework
      end
    end
  end
end
