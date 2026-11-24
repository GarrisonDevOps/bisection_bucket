# frozen_string_literal: true

module Geo
  class PackagesDebianProjectComponentFileRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :packages_debian_project_component_file, class_name: 'Packages::Debian::ProjectComponentFile'

    def self.model_class
      ::Packages::Debian::ProjectComponentFile
    end

    def self.model_foreign_key
      :packages_debian_project_component_file_id
    end
  end
end
