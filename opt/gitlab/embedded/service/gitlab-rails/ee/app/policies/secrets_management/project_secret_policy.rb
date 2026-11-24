# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretPolicy < BasePolicy
    delegate { @subject.project }
  end
end
