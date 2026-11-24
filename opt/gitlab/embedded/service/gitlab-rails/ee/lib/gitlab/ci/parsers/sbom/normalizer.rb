# frozen_string_literal: true

module Gitlab
  module Ci
    module Parsers
      module Sbom
        # Reads the components of a CycloneDX SBOM that no GitLab analyzer wrote, after the SBOM has passed
        # schema validation, and returns one entry for each package at each source file that declares it, or at the
        # default location when the SBOM records no file for the package. An entry holds the data of the component and
        # the source file it is listed at. An operating system package, such as a `deb` package of an image, is
        # installed and not declared by a source file, so it gets one entry with no file. A component typed
        # `framework` is read as a library.
        class Normalizer
          DEFAULT_PATH = '3rd Party Input File Path Unknown'
          FRAMEWORK_TYPE = 'framework'
          LIBRARY_TYPE = 'library'

          Entry = Struct.new(:data, :path)

          def initialize(data)
            @data = data
          end

          def entries
            components.map { |component_data| entry_of(component_data) }
          end

          private

          attr_reader :data

          def entry_of(component_data)
            component = library_typed(component_data)
            return Entry.new(component, nil) if operating_system_package?(component)

            Entry.new(component, DEFAULT_PATH)
          end

          # Some generators, such as cdxgen, type an ordinary library `framework`, and ingestion keeps only the
          # components typed `library`. The package URL checks of ingestion then decide what is ingested.
          def library_typed(component_data)
            return component_data unless component_data['type'] == FRAMEWORK_TYPE

            component_data.merge('type' => LIBRARY_TYPE)
          end

          # A package URL that cannot be parsed is not read as an operating system package. The parser then skips
          # the component and logs the reason.
          def operating_system_package?(component_data)
            return false unless component_data['purl']

            purl_type = ::Sbom::PackageUrl.parse(component_data['purl']).type

            ::Enums::Sbom.container_scanning_purl_type?(purl_type)
          rescue ::Sbom::PackageUrl::InvalidPackageUrl
            false
          end

          def components
            data['components'] || []
          end
        end
      end
    end
  end
end
