# frozen_string_literal: true

module PackageMetadata
  module Ingestion
    module CompressedPackage
      class LicenseIngestionTask
        include ::Gitlab::Utils::StrongMemoize

        def initialize(import_data, identifier_map, expression_map)
          @import_data = import_data
          @identifier_map = identifier_map
          @expression_map = expression_map
        end

        def self.execute(import_data, identifier_map, expression_map)
          new(import_data, identifier_map, expression_map).execute
        end

        def execute
          identifier_map.merge!(existing_identifiers)
          expression_map.merge!(existing_expressions)

          identifiers = PackageMetadata::License.bulk_upsert!(new_identifiers, unique_by: ['spdx_identifier'],
            returns: %w[spdx_identifier id])
          identifier_map.merge!(identifiers.to_h)

          expressions = PackageMetadata::License.bulk_upsert!(new_expressions, unique_by: ['spdx_expression'],
            returns: %w[spdx_expression id])
          expression_map.merge!(expressions.to_h)
        end

        private

        attr_reader :import_data
        attr_accessor :identifier_map, :expression_map

        def spdx_identifiers
          import_data.flat_map(&:spdx_identifiers).reject(&:blank?).sort.uniq
        end
        strong_memoize_attr :spdx_identifiers

        def spdx_expressions
          import_data.flat_map(&:spdx_expressions).reject(&:blank?).sort.uniq
        end
        strong_memoize_attr :spdx_expressions

        def existing_identifiers
          PackageMetadata::License.with_spdx_identifiers(spdx_identifiers)
            .to_h { |license| [license.spdx_identifier, license.id] }
        end

        def existing_expressions
          PackageMetadata::License.with_spdx_expressions(spdx_expressions)
            .to_h { |license| [license.spdx_expression, license.id] }
        end

        def new_identifiers
          spdx_identifiers
            .reject { |id| identifier_map[id] }
            .map { |id| build_identifier(id) }
        end

        def new_expressions
          spdx_expressions
            .reject { |expression| expression_map[expression] }
            .map { |expression| build_expression(expression) }
        end

        def build_identifier(spdx_identifier)
          PackageMetadata::License.new(spdx_identifier: spdx_identifier, created_at: now, updated_at: now)
        end

        def build_expression(spdx_expression)
          PackageMetadata::License.new(spdx_expression: spdx_expression, created_at: now, updated_at: now)
        end

        def now
          @now ||= Time.zone.now
        end
      end
    end
  end
end
