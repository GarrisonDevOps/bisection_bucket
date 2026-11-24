# frozen_string_literal: true

module Geo
  class PackageFileState < ApplicationRecord
    self.table_name = 'packages_package_file_states'
    include ::Geo::VerificationStateDefinition

    belongs_to :package_file, class_name: 'Packages::PackageFile',
      inverse_of: :package_file_state

    validates :verification_state, :package_file, presence: true
  end
end
