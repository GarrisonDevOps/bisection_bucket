# frozen_string_literal: true

module Types
  module AlertManagement
    class HttpIntegrationType < BaseObject
      graphql_name 'AlertManagementHttpIntegration'
      description 'An endpoint and credentials used to accept alerts for a project'

      implements Types::AlertManagement::IntegrationType

      authorize :read_http_integration
    end
  end
end

Types::AlertManagement::HttpIntegrationType.prepend_mod
