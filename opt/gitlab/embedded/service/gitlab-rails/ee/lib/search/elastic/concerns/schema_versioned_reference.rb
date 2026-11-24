# frozen_string_literal: true

module Search
  module Elastic
    module Concerns
      # Shared behavior for Elasticsearch reference classes that gate fields behind
      # schema versions tied to advanced search migrations.
      #
      # Including classes must define:
      # - `DOC_TYPE`: the value stored in the indexed `type` field.
      # - `SCHEMA_VERSIONS`: a Hash mapping schema version (Integer) to the migration name
      #   (Symbol) that must have finished before that version is considered active, or
      #   `nil` for baseline versions that don't require a migration.
      #
      # Including classes may optionally define:
      # - `FIELDS_WITH_MIGRATIONS`: a Hash mapping field name (String) to the migration
      #   name (Symbol) that must have finished before `#set_field` assigns that field.
      #   Defaults to `{}` when not defined, meaning no field is gated.
      module SchemaVersionedReference
        extend ActiveSupport::Concern

        private

        # Conditionally sets `fields[name]` to the value yielded by the block, unless the
        # field is still waiting on its associated migration to finish.
        def set_field(fields, name)
          return if waiting_on_migration?(name)

          fields[name] = yield
        end

        def waiting_on_migration?(field)
          migration_name = fields_with_migrations[field]

          return false if migration_name.blank?

          !::Elastic::DataMigrationService.migration_has_finished?(migration_name)
        end

        def fields_with_migrations
          return {} unless self.class.const_defined?(:FIELDS_WITH_MIGRATIONS, false)

          self.class::FIELDS_WITH_MIGRATIONS
        end

        def internal_es_fields
          {
            schema_version: fetch_schema_version,
            type: self.class::DOC_TYPE
          }.with_indifferent_access
        end

        def fetch_schema_version
          self.class::SCHEMA_VERSIONS.sort.reverse_each do |version, migration|
            break version if migration.nil? || ::Elastic::DataMigrationService.migration_has_finished?(migration)
          end
        end
      end
    end
  end
end
