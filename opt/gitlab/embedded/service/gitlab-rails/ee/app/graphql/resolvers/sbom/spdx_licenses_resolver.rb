# frozen_string_literal: true

module Resolvers
  module Sbom
    class SpdxLicensesResolver < BaseResolver
      type [::Types::Sbom::SpdxLicenseType], null: true

      description 'List of SPDX licenses from the SPDX licence catalogue.'

      def resolve(**_args)
        raise_resource_not_available_error! unless current_user

        ::Gitlab::SPDX::Catalogue.latest_licenses
      end
    end
  end
end
