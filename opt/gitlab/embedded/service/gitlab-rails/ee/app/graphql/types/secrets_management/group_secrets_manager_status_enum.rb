# frozen_string_literal: true

module Types
  module SecretsManagement
    class GroupSecretsManagerStatusEnum < BaseEnum
      graphql_name 'GroupSecretsManagerStatus'
      description 'Values for the group secrets manager status'

      include BaseSecretsManagerStatusEnum
    end
  end
end
