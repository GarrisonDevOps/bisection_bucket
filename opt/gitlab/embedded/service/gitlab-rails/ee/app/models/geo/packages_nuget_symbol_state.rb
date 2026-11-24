# frozen_string_literal: true

module Geo
  class PackagesNugetSymbolState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    belongs_to :packages_nuget_symbol, inverse_of: :packages_nuget_symbol_state, class_name: 'Packages::Nuget::Symbol'

    validates :verification_state, :packages_nuget_symbol, presence: true
  end
end
