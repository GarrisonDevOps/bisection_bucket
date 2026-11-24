# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      # UPSERTs the identifiers for the given findings and
      # sets the identifier IDs for each `finding_map`.
      class IngestIdentifiers < AbstractTask
        include Gitlab::Ingestion::BulkInsertableTask
        include Gitlab::Utils::StrongMemoize

        self.model = Vulnerabilities::Identifier
        self.unique_by = %i[project_id fingerprint]
        self.uses = %i[project_id fingerprint id]
        # A slice of 50 findings can carry up to 1000 unique identifiers. Upserting
        # them in one statement can exceed the statement timeout, so cap the row
        # count per INSERT to keep each statement within its own timeout window.
        self.batch_size = 50

        # `updated_at` is deliberately absent: it is rewritten on every scan, so
        # including it would mark every row changed and defeat the filter.
        COMPARED_ATTRIBUTES = %i[external_id external_type name url].freeze

        private

        def after_ingest
          finding_maps.each { |finding_map| finding_map.set_identifier_ids_by(fingerprint_map[finding_map.project.id]) }
        end

        # Ids come from two places once unchanged rows are filtered out: the rows we
        # upserted return theirs, and the rows we skipped already had one.
        def fingerprint_map
          map = Hash.new { |hash, key| hash[key] = {} }

          existing_identifiers.each_value do |identifier|
            map[identifier.project_id][identifier.fingerprint] = identifier.id
          end
          return_data.each { |project_id, fingerprint, id| map[project_id][fingerprint] = id }

          map
        end
        strong_memoize_attr :fingerprint_map

        # Important Note:
        #   Sorting identifiers is important to prevent having deadlock
        #   errors which can happen if other threads try to import the same
        #   identifiers in different order.
        def attributes
          changed_identifiers.sort_by do |identifier_data|
            [identifier_data[:project_id], identifier_data[:fingerprint]]
          end
        end

        def changed_identifiers
          report_identifiers.reject { |identifier_data| unchanged?(identifier_data) }
        end

        def unchanged?(identifier_data)
          existing = existing_identifiers[key_for(identifier_data)]
          return false unless existing

          COMPARED_ATTRIBUTES.all? { |attribute| existing.read_attribute(attribute) == identifier_data[attribute] }
        end

        # Grouped by project so the lookup stays on the (project_id, fingerprint) index
        # instead of forming a cross product, which matters for CVS ingestion where a
        # batch spans many projects.
        def existing_identifiers
          report_identifiers.group_by { |identifier_data| identifier_data[:project_id] }
            .each_with_object({}) do |(project_id, rows), map|
              ::Vulnerabilities::Identifier
                .by_projects(project_id)
                .with_fingerprint(rows.map { |row| row[:fingerprint] })
                .each { |identifier| map[[identifier.project_id, identifier.fingerprint]] = identifier }
            end
        end
        strong_memoize_attr :existing_identifiers

        def key_for(identifier_data)
          [identifier_data[:project_id], identifier_data[:fingerprint]]
        end

        def report_identifiers
          @report_identifiers ||= finding_maps
            .flat_map(&:identifier_data)
            .uniq { |identifier_data| [identifier_data[:project_id], identifier_data[:fingerprint]] }
        end
      end
    end
  end
end
