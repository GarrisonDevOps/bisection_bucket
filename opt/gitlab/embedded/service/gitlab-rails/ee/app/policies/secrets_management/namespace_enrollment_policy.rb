# frozen_string_literal: true

module SecretsManagement
  class NamespaceEnrollmentPolicy < BasePolicy
    delegate { @subject.namespace }
  end
end
