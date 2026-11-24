# frozen_string_literal: true

module API
  module Entities
    module Terraform
      class ModuleVersions < Grape::Entity
        expose :modules, documentation: { type: 'Hash', is_array: true }
      end
    end
  end
end
