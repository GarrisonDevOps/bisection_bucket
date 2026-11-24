# frozen_string_literal: true

module SecretsManagement
  class GroupSecretsManagerPolicy < BasePolicy
    delegate { @subject.group }
  end
end
