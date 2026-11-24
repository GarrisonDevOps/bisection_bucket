# frozen_string_literal: true

module ComplianceManagement
  class FrameworkPolicy < BasePolicy
    delegate { @subject.namespace }

    condition(:compliance_framework_available, scope: :subject) do
      @subject.namespace.feature_available?(:custom_compliance_frameworks)
    end

    condition(:read_root_group) do
      can?(:read_group, @subject.namespace.root_ancestor)
    end

    rule { read_root_group & compliance_framework_available }.policy do
      enable :read_compliance_framework
      enable :read_compliance_adherence_report
    end

    rule { can?(:admin_compliance_framework) & compliance_framework_available }.policy do
      enable :read_compliance_framework
      enable :read_compliance_adherence_report
    end
  end
end
