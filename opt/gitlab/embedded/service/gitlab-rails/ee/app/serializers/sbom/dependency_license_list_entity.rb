# frozen_string_literal: true

module Sbom
  class DependencyLicenseListEntity < Grape::Entity
    present_collection true, :licenses

    expose :licenses, using: ::DependencyEntity::LicenseEntity
  end
end
