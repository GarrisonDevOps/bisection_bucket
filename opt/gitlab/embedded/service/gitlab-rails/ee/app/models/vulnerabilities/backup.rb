# frozen_string_literal: true

module Vulnerabilities
  class Backup < SecApplicationRecord
    include PartitionedTable
    include BulkInsertSafe

    class << self
      attr_reader :column_mapping, :original_model

      def backup_of(original_model, column_mapping: {})
        @original_model = original_model
        @column_mapping = column_mapping
      end

      # Keys are the attribute names on original model,
      # values are the corresponding attribute names on the backup model.
      def column_mappings
        @column_mappings ||= @column_mapping.merge({ id: :original_record_identifier, project_id: :project_id })
      end

      def data_columns
        @data_columns ||= original_model.columns.reject { |column| mapped_column?(column.name) }
      end

      def insert_sql_template
        @insert_sql ||= <<~SQL
          INSERT INTO #{original_model.table_name} #{original_table_definition}
          VALUES
            %{values}
          #{on_conflict}
          RETURNING ID
        SQL
      end

      # There is always a single mapping provided
      # while configuring the backup model so we can
      # safely assume that the first one is the FK.
      def parent_column
        @parent_column ||= column_mappings.each_value.first
      end

      private

      def on_conflict
        ''
      end

      def original_table_definition
        ordered_column_names.join(', ')
                            .then { |column_names| "(#{column_names})" }
      end

      def ordered_column_names
        column_mappings.keys + data_columns.map(&:name)
      end

      def mapped_column?(column_name)
        column_mappings.has_key?(column_name.to_sym)
      end
    end

    self.abstract_class = true
    self.table_name_prefix = 'backup_'

    belongs_to :project, optional: false

    attribute :data, Gitlab::Database::Type::JsonPgSafe.new(replace_with: '\\\\\u0000')

    validates :original_record_identifier, presence: true, numericality: { only_integer: true, greater_than: 0 }
    validates :data, presence: true, json_schema: { filename: 'vulnerability_backup_data' } # rubocop:disable Database/JsonbSizeLimit -- We can't add a limit for this attribute

    scope :by_parents, ->(parents) { where(parent_column => parents) }
    scope :by_original_ids, ->(ids) { where(original_record_identifier: ids) }

    def as_tuple
      all_values.map { |value| connection.quote(value) }
                .join(', ')
                .then { |tuple| "(#{tuple})" }
    end

    private

    delegate :original_model, to: :'self.class', private: true

    def all_values
      mapped_values + data_values
    end

    def mapped_values
      self.class.column_mappings.values.map { |column_name| read_attribute(column_name) }
    end

    def data_values
      self.class.data_columns.map { |column| value_for(column) }
    end

    def value_for(column)
      data.has_key?(column.name) ? data[column.name] : column.default
    end
  end
end
