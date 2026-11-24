# frozen_string_literal: true

module PackageMetadata # rubocop:disable Gitlab/BoundedContexts -- follows existing package_metadata services pattern
  class CompressedPackageDataObjectBase
    attr_accessor :purl_type, :lowest_version, :highest_version

    def spdx_expressions
      []
    end

    def default_expressions
      []
    end

    def name
      ::Sbom::PackageUrl::Normalizer.new(type: purl_type, text: @name)
        .normalize_name
    end
  end
end
