# frozen_string_literal: true

module SecretsManagement
  class GroupSecretPolicy < BasePolicy
    delegate { @subject.group }
  end
end
