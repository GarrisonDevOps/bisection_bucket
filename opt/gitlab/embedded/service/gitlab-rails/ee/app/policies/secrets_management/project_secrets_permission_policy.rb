# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretsPermissionPolicy < BasePolicy
    delegate { @subject.resource }
  end
end
