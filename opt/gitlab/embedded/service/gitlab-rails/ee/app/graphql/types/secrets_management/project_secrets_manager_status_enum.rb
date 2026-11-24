# frozen_string_literal: true

module Types
  module SecretsManagement
    class ProjectSecretsManagerStatusEnum < BaseEnum
      graphql_name 'ProjectSecretsManagerStatus'
      description 'Values for the project secrets manager status'

      include BaseSecretsManagerStatusEnum
    end
  end
end
