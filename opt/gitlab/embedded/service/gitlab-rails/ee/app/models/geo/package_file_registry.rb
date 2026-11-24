# frozen_string_literal: true

module Geo
  class PackageFileRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :package_file, class_name: 'Packages::PackageFile'

    def self.model_class
      ::Packages::PackageFile
    end

    def self.model_foreign_key
      :package_file_id
    end
  end
end
