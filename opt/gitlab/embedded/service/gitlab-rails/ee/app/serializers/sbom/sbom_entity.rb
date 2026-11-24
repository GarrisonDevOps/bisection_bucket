# frozen_string_literal: true

module Sbom
  class SbomLicenseEntity < Grape::Entity
    include Gitlab::Utils::StrongMemoize

    expose :license do
      expose :spdx_identifier,
        as: :id,
        override: true,
        if: proc { |license| valid_id?(license) },
        expose_nil: false

      expose :name,
        override: true,
        if: proc { |license| license[:name].present? && !valid_id?(license) },
        expose_nil: false

      expose :url,
        override: true,
        if: proc { |license| valid_id?(license) },
        expose_nil: false do |license|
        ::Gitlab::Ci::Reports::LicenseScanning::License.spdx_url(license[:spdx_identifier])
      end
    end

    private

    def valid_id?(license)
      strong_memoize_with(:valid, license) do
        is_unknown_id = Gitlab::Ci::Reports::LicenseScanning::License.unknown_spdx_identifier?(license)
        is_blank_id = license[:spdx_identifier].blank?
        !is_unknown_id && !is_blank_id
      end
    end
  end

  class SbomComponentsEntity < Grape::Entity
    expose :name
    expose :version, expose_nil: false
    expose :purl, expose_nil: false
    expose :type
    expose :licenses, expose_nil: false do |component|
      next nil if component[:licenses].nil? || component[:licenses].empty?

      component[:licenses].map do |license|
        SbomLicenseEntity.represent(license)
      end
    end
  end

  class SbomMetadataEntity < Grape::Entity
    expose :timestamp, expose_nil: false
    expose :authors
    expose :properties
    expose :tools
  end

  class SbomAttributes < Grape::Entity
    expose :bom_format, as: :bomFormat
    expose :spec_version, as: :specVersion
    expose :serial_number, as: :serialNumber
    expose :version
  end

  class SbomEntity < Grape::Entity
    expose :sbom_attributes, merge: true, using: SbomAttributes
    expose :metadata, using: SbomMetadataEntity
    expose :components, using: SbomComponentsEntity
  end
end
