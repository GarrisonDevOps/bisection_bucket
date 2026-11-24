# frozen_string_literal: true

module Geo
  class PackagesDebianProjectComponentFileState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    belongs_to :packages_debian_project_component_file, inverse_of: :packages_debian_project_component_file_state,
      class_name: 'Packages::Debian::ProjectComponentFile'

    validates :verification_state, :packages_debian_project_component_file, presence: true

    before_validation :copy_project_id, on: :create

    private

    def copy_project_id
      self.project_id ||= packages_debian_project_component_file&.project_id
    end
  end
end
