# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretsManagerPolicy < BasePolicy
    delegate { @subject.project }
  end
end
