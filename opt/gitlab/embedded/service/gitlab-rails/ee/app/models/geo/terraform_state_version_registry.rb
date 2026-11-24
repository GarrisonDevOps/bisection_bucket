# frozen_string_literal: true

module Geo
  class TerraformStateVersionRegistry < Geo::BaseRegistry
    include Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :terraform_state_version, class_name: 'Terraform::StateVersion'

    def self.model_class
      ::Terraform::StateVersion
    end

    def self.model_foreign_key
      :terraform_state_version_id
    end
  end
end
