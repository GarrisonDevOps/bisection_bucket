# frozen_string_literal: true

module Sbom
  module Exporters
    class CsvService
      LIST_DELIMITER = '; '
      LIST_ROW_SEPARATOR = ''

      # Lightweight decorator that overrides licenses on an Sbom::Occurrence
      # without mutating the ActiveRecord object.
      # NOTE: is_a?(Sbom::Occurrence) returns false on this wrapper.
      # This is acceptable because CsvBuilder only calls methods, never checks types.
      class OccurrenceWithOverriddenLicenses < SimpleDelegator
        def initialize(occurrence, overridden_licenses)
          super(occurrence)
          @overridden_licenses = overridden_licenses
        end

        def licenses
          @overridden_licenses
        end
      end

      class << self
        def combine_parts(part_files)
          Tempfile.open do |export|
            export << header

            part_files.each { |file| write_part(export, file) }

            if block_given?
              yield export
            else
              export.rewind
              export.read
            end
          end
        end

        def header
          CSV.generate_line(mapping.keys)
        end

        def mapping
          {
            s_('DependencyListExport|Name') => 'component_name',
            s_('DependencyListExport|Version') => 'version',
            s_('DependencyListExport|Packager') => 'package_manager',
            s_('DependencyListExport|Location') => ->(occurrence) { occurrence.location[:blob_path] },
            s_('DependencyListExport|License Identifiers') => ->(occurrence) {
              # rubocop:disable CodeReuse/ActiveRecord -- `licenses` is an array
              # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- `licenses` is an array
              serialize_list(occurrence.licenses.pluck('spdx_identifier'))
              # rubocop:enable CodeReuse/ActiveRecord
              # rubocop:enable Database/AvoidUsingPluckWithoutLimit
            },
            s_('DependencyListExport|Project') => ->(occurrence) { occurrence.project&.full_path },
            s_('DependencyListExport|Vulnerabilities Detected') => 'vulnerability_count',
            s_('DependencyListExport|Vulnerability IDs') => ->(occurrence) {
              serialize_list(occurrence.vulnerabilities.map(&:id))
            }
          }
        end

        private

        def serialize_list(list)
          list.to_csv(col_sep: LIST_DELIMITER, row_sep: LIST_ROW_SEPARATOR)
        end

        def write_part(export, file)
          file.open do |stream|
            # Read past the CSV header
            stream.readline

            stream.each_line do |line|
              # The encoding of the parts is read as ASCI-8BIT.
              # We need to force the encoding to utf-8 to avoid a write failure due to
              # wide-chars used in place like group names.
              # See:
              # https://github.com/carrierwaveuploader/carrierwave/issues/1583
              # https://gitlab.com/gitlab-org/gitlab/-/blob/0aa846a1baa08b1f6f11b2711f8f6bf880542a46/lib/gitlab/http_io.rb
              export << line.force_encoding(Encoding::UTF_8)
            end
          end
        end
      end

      attr_reader :sbom_occurrences

      def initialize(_export, sbom_occurrences)
        @sbom_occurrences = sbom_occurrences
      end

      def generate(&block)
        csv_builder.render(&block)
      end

      alias_method :generate_part, :generate

      private

      def occurrences
        Enumerator.new do |enumerator|
          iterator.each_batch do |batch|
            occurrences = Sbom::Occurrence
              .id_in(batch.map(&:id))
              .with_version
              .with_source
              .with_project_namespace
              .with_vulnerabilities

            occurrences.each do |occurrence|
              # Filter out orphaned records that don't have a project.
              # Tracked in https://gitlab.com/gitlab-org/gitlab/-/issues/541931
              next unless occurrence.project

              enumerator << with_license_overrides(occurrence)
            end
          end
        end
      end

      def with_license_overrides(occurrence)
        applicator = applicator_for_project(occurrence.project)
        return occurrence unless applicator.overrides?

        overridden = applicator.apply(occurrence.licenses || [], purl: occurrence.purl&.to_s)

        return occurrence if overridden.equal?(occurrence.licenses)

        # Wrap in a decorator that overrides licenses without mutating the AR object
        OccurrenceWithOverriddenLicenses.new(occurrence, overridden)
      end

      def applicator_for_project(project)
        @applicators ||= {}
        @applicators[project.id] ||= ::Security::LicenseOverrideApplicator.new(project)
      end

      def iterator
        scope = sbom_occurrences.select(:id, :traversal_ids).order_traversal_ids_asc

        Gitlab::Pagination::Keyset::Iterator.new(
          scope: scope,
          use_union_optimization: false
        )
      end

      def csv_builder
        @csv_builder ||= CsvBuilder.new(occurrences, self.class.mapping, replace_newlines: true)
      end
    end
  end
end
