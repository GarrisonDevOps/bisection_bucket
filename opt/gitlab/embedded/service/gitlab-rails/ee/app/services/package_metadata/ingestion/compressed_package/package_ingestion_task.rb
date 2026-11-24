# frozen_string_literal: true

module PackageMetadata
  module Ingestion
    module CompressedPackage
      class PackageIngestionTask
        Error = Class.new(StandardError)

        def initialize(import_data, identifier_map, expression_map)
          @import_data = import_data
          @identifier_map = identifier_map
          @expression_map = expression_map
        end

        def self.execute(import_data, identifier_map, expression_map)
          new(import_data, identifier_map, expression_map).execute
        end

        def execute
          PackageMetadata::Package.bulk_upsert!(valid_packages, unique_by: %w[purl_type name])
        end

        private

        attr_reader :import_data, :identifier_map, :expression_map

        # validate checks the list of provided package models and returns
        # only those which are valid and logs the invalid packages as an error
        def valid_packages
          packages.filter do |package|
            if package.valid?
              true
            else
              Gitlab::ErrorTracking.track_exception(
                Error.new(
                  "invalid package"),
                purl_type: package.purl_type,
                name: package.name,
                errors: package.errors.to_hash
              )

              false
            end
          end.uniq(&:name)
        end

        def packages
          import_data.map do |data_object|
            builder.build(data_object)
          end
        end

        def builder
          @builder ||= PackageBuilder.new(identifier_map, expression_map)
        end

        class PackageBuilder
          def initialize(identifier_map, expression_map)
            @identifier_map = identifier_map
            @expression_map = expression_map
          end

          # build a new model object by assigning attributes and converting
          # data_object licenses into the compressed tuple expected by the
          # model, resolving each license string through the map of its
          # declared role
          def build(data_object)
            PackageMetadata::Package.new(
              name: data_object.name,
              purl_type: data_object.purl_type,
              licenses: [
                identifier_ids(data_object.default_identifiers) + expression_ids(data_object.default_expressions),
                data_object.lowest_version,
                data_object.highest_version,
                convert_other(data_object.other_licenses)
              ],
              created_at: now,
              updated_at: now
            )
          end

          private

          attr_reader :identifier_map, :expression_map

          def identifier_ids(identifiers)
            identifiers.map { |identifier| identifier_map[identifier] }
          end

          def expression_ids(expressions)
            expressions.map { |expression| expression_map[expression] }
          end

          # convert other_licenses by converting the data_object's list of hashes
          # into a list of tuples, resolving each license string through the map
          # of its declared role
          def convert_other(other_licenses)
            other_licenses.map do |hash|
              ids = identifier_ids(hash.fetch('licenses', [])) + expression_ids(hash.fetch('expressions', []))
              [ids, hash['versions']]
            end
          end

          def now
            @now ||= Time.zone.now
          end
        end
      end
    end
  end
end
