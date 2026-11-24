# frozen_string_literal: true

module Geo
  class PackagesNugetSymbolRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :packages_nuget_symbol, class_name: 'Packages::Nuget::Symbol'

    def self.model_class
      ::Packages::Nuget::Symbol
    end

    def self.model_foreign_key
      :packages_nuget_symbol_id
    end
  end
end
