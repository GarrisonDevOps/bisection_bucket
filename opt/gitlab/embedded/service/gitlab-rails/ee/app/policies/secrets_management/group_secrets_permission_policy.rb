# frozen_string_literal: true

module SecretsManagement
  class GroupSecretsPermissionPolicy < BasePolicy
    delegate { @subject.resource }
  end
end
