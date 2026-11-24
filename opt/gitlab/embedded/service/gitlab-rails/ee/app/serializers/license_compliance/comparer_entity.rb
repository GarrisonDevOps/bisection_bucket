# frozen_string_literal: true

module LicenseCompliance
  class ComparerEntity < Grape::Entity
    include RequestAwareEntity

    expose :new_licenses, using: ::Security::LicensePolicyEntity
    expose :existing_licenses, using: ::Security::LicensePolicyEntity
    expose :removed_licenses, using: ::Security::LicensePolicyEntity

    expose :approval_required do |_|
      request.approval_required
    end

    expose :has_denied_licenses do |_|
      request.has_denied_licenses
    end
  end
end
