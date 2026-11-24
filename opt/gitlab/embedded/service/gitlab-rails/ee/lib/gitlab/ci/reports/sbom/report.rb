# frozen_string_literal: true

module Gitlab
  module Ci
    module Reports
      module Sbom
        class Report
          # This represents the attributes defined in cycloneDX Schema
          BOM_FORMAT = 'CycloneDX'
          SPEC_VERSION = '1.4'
          VERSION = 1

          attr_reader :source, :errors
          attr_accessor :sbom_attributes, :metadata, :components

          # Whether third-party SBOM support is enabled for the project of this report.
          attr_reader :third_party_sbom_support

          def initialize(third_party_sbom_support: false)
            @sbom_attributes = {
              bom_format: BOM_FORMAT,
              spec_version: SPEC_VERSION,
              serial_number: Gitlab::UUID.urn,
              version: VERSION
            }
            @components = []
            @metadata = ::Gitlab::Ci::Reports::Sbom::Metadata.new
            @dependencies = DependencyAdjacencyList.new
            @errors = []
            @third_party_sbom_support = third_party_sbom_support
          end

          # Copies share the dependency graph and metadata, and get their own errors and attributes.
          def initialize_copy(other)
            super
            @errors = other.errors.dup
            @sbom_attributes = other.sbom_attributes.dup
          end

          def valid?
            errors.empty?
          end

          # Whether the report is read as an SBOM of another generator: it has third-party SBOM support and its
          # SBOM records no property that starts with the GitLab prefix.
          def third_party?
            third_party_sbom_support &&
              Array(metadata.properties).none? do |property|
                property['name'].to_s.start_with?(::Gitlab::Ci::Parsers::Sbom::CyclonedxProperties::GITLAB_PREFIX)
              end
          end

          def add_error(error)
            errors << error
          end

          def set_source(source)
            self.source = source
          end

          def add_component(component)
            components << component
            dependencies.add_component_info(component.ref, component.name, component.version)
          end

          def set_metadata_component(component)
            dependencies.add_component_info(component.ref)
          end

          def add_dependency(parent, child)
            dependencies.add_edge(parent, child)
          end

          def ensure_ancestors!
            components.each do |component|
              component.ancestors = ancestors_for(component.ref)
            end
          end

          # Ingestion expects one report for each manifest location. This returns the reports that follow that
          # convention: one for each path of the components, and one more for the components without a path.
          # A component has one path, so a package recorded at several files is several components.
          def split_by_path
            return [self] unless components.any? { |component| component.path.present? }

            by_path = components.group_by(&:path)
            no_path = by_path.delete(nil)
            reports = by_path.map { |path, group| new_report(group, input_file_source(path)) }
            reports << new_report(no_path, source) if no_path
            reports
          end

          private

          def new_report(report_components, report_source)
            dup.tap do |report|
              report.components = report_components
              report.set_source(report_source)
            end
          end

          # A source that names the path as its input file, the form that ingestion reads.
          def input_file_source(path)
            Source.new(type: :dependency_scanning, data: { 'input_file' => { 'path' => path } })
          end

          def ancestors_for(ref)
            dependencies.ancestors_for(ref)
          end

          attr_writer :source
          attr_reader :dependencies
        end
      end
    end
  end
end
