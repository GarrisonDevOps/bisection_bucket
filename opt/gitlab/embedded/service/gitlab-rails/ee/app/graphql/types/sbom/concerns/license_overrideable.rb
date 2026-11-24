# frozen_string_literal: true

module Types
  module Sbom
    module Concerns
      module LicenseOverrideable
        extend ActiveSupport::Concern

        private

        def apply_license_overrides(licenses)
          return licenses unless object.respond_to?(:project) &&
            ::Security::LicenseOverrideApplicator.experiment_enabled_for_project?(object.project)

          applicator = license_override_applicator
          return licenses unless applicator.overrides?

          dep_purl = occurrence_purl
          return licenses unless dep_purl

          result = applicator.apply(licenses, purl: dep_purl)

          # Enrich override licenses with GraphQL-specific fields
          result.map do |license|
            if license['project_id'].nil?
              license.merge(
                'project_id' => object.project_id,
                'occurrence_uuid' => object.uuid
              )
            else
              license
            end
          end
        end

        def occurrence_purl
          return unless object.purl_type.present?

          base = "pkg:#{object.purl_type}/#{object.component_name}"
          version = object.version
          version.present? ? "#{base}@#{version}" : base
        end

        def license_override_applicator
          context[:security_license_override_applicators] ||= {}
          context[:security_license_override_applicators][object.project_id] ||=
            ::Security::LicenseOverrideApplicator.new(object.project)
        end
      end
    end
  end
end
