# frozen_string_literal: true

module Gitlab
  module Encryption
    module DbKeyBaseRotation
      # Every table with attr_encrypted attributes or encrypted token fields that use a `db_key_base` key.
      #
      # STI subclasses and models sharing a table are merged, so each row is rewritten once.
      class Registry
        DefinitionMismatchError = Class.new(StandardError)

        # Background migration models are stripped-down copies frozen in time, so they must not become
        # the model a table is queried with.
        BACKGROUND_MIGRATION_MODEL = /\A(EE::)?Gitlab::BackgroundMigration::/

        # @return [Array<Table>] the tables, by name
        def self.tables
          new.tables
        end

        # @return [Array<Table>]
        def tables
          Rails.application.eager_load! unless Rails.application.config.eager_load

          tables_by_name.sort.map { |name, entry| Table.new(name, entry[:model], entry[:columns].values) }
        end

        private

        def tables_by_name
          models.each_with_object({}) do |model, tables|
            columns = encrypted_columns(model)
            next if columns.empty?

            entry = tables[model.table_name] ||= { model: model.base_class, columns: {} }
            columns.each { |column| merge_column(entry[:columns], model, column) }
          end
        end

        def merge_column(table_columns, model, column)
          existing = table_columns[column.columns]

          if existing.nil?
            table_columns[column.columns] = column
          elsif existing.definition != column.definition
            raise DefinitionMismatchError,
              "#{model.name} encrypts #{model.table_name}.#{column.columns.first} differently from another model"
          end
        end

        def encrypted_columns(model)
          attr_encrypted_columns(model) + token_columns(model)
        end

        def attr_encrypted_columns(model)
          return [] unless model.include?(Gitlab::EncryptedAttribute)

          model.attr_encrypted_encrypted_attributes.keys
            .select { |attribute| AttrEncryptedColumn.supported?(model, attribute) }
            .map { |attribute| AttrEncryptedColumn.new(model, attribute) }
        end

        def token_columns(model)
          return [] unless model.include?(TokenAuthenticatable)

          model.encrypted_token_authenticatable_fields.map { |field| TokenColumn.new(field) }
        end

        def models
          ApplicationRecord.descendants.reject do |model|
            model.abstract_class? || model.name.nil? || model.name.match?(BACKGROUND_MIGRATION_MODEL)
          end
        end
      end
    end
  end
end
