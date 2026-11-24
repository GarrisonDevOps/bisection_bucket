# frozen_string_literal: true

module Geo
  class TerraformStateVersionState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    belongs_to :terraform_state_version, class_name: 'Terraform::StateVersion',
      inverse_of: :terraform_state_version_state

    validates :verification_state, :terraform_state_version, presence: true
  end
end
