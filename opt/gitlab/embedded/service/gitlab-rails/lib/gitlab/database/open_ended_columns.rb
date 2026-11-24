# frozen_string_literal: true

module Gitlab
  module Database
    # Finds open-ended (unbounded-width) columns that have no size-limiting CHECK constraint.
    class OpenEndedColumns
      TEXT_TYPE_NAMES = %w[text].freeze
      BINARY_TYPE_NAMES = %w[bytea].freeze
      JSON_TYPE_NAMES = %w[jsonb json].freeze
      # Kept out of TEXT_TYPE_NAMES: only varchar without a length (atttypmod = -1) is open-ended.
      VARCHAR_TYPE_NAME = 'varchar'

      # Only an upper bound (`<`, `<=`, `=`) limits size. PostgreSQL quotes reserved-word
      # column names and prints length checks on varchar and json with a `::text` cast.
      BOUNDING_CHECK_PATTERNS = {
        text: '(?:char_length|length)\s*\(\s*(?:"?%<column>s"?|\("?%<column>s"?\)::text)\s*\)\s*(?:<=?|=)(?!>)',
        binary: 'octet_length\s*\(\s*"?%<column>s"?\s*\)\s*(?:<=?|=)(?!>)',
        json: '(?:octet_length|char_length|length)\s*\(\s*\("?%<column>s"?\)::text\s*\)\s*(?:<=?|=)(?!>)'
      }.freeze

      Column = Struct.new(:table_name, :column_name, :kind, keyword_init: true) do
        def identifier
          "#{table_name}.#{column_name}"
        end

        def bounded_by?(check_definition)
          pattern = BOUNDING_CHECK_PATTERNS.fetch(kind)
          bounding_check = Regexp.new(format(pattern, column: Regexp.escape(column_name)))
          bounding_check.match?(check_definition)
        end
      end

      def self.unbounded_identifiers
        identifiers = []

        Gitlab::Database::EachDatabase.each_connection do |connection, _database_name|
          identifiers.concat(new(connection).unbounded_identifiers)
        end

        # Shared schemas are owned by every connection, so their tables appear more than once.
        identifiers.uniq.sort
      end

      def initialize(connection)
        @connection = connection
      end

      def unbounded_identifiers
        checks_by_table = check_definitions_by_table

        open_ended_columns.filter_map do |column|
          table_checks = checks_by_table[column.table_name] || []
          next if table_checks.any? { |check_definition| column.bounded_by?(check_definition) }

          column.identifier
        end.sort
      end

      private

      attr_reader :connection

      def open_ended_columns
        connection.select_all(open_ended_columns_sql).filter_map do |row|
          next unless owned_by_connection?(row['table_name'])

          Column.new(table_name: row['table_name'], column_name: row['column_name'], kind: kind_for(row['base_type']))
        end
      end

      # Every database holds tables it doesn't own (locked for writes), so only
      # report tables whose gitlab_schema belongs to this connection.
      def owned_by_connection?(table_name)
        owned_schemas.include?(Gitlab::Database::GitlabSchema.table_schema!(table_name))
      end

      def owned_schemas
        @owned_schemas ||= Gitlab::Database.gitlab_schemas_for_connection(connection)
      end

      def kind_for(base_type)
        return :text if TEXT_TYPE_NAMES.include?(base_type) || base_type == VARCHAR_TYPE_NAME
        return :binary if BINARY_TYPE_NAMES.include?(base_type)

        :json
      end

      def open_ended_columns_sql
        text_types = quote_type_names(TEXT_TYPE_NAMES)
        binary_types = quote_type_names(BINARY_TYPE_NAMES)
        json_types = quote_type_names(JSON_TYPE_NAMES)
        varchar = connection.quote(VARCHAR_TYPE_NAME)

        <<~SQL
          SELECT
            table_class.relname AS table_name,
            attribute.attname AS column_name,
            base_type.typname AS base_type
          FROM pg_attribute attribute
          JOIN pg_class table_class ON table_class.oid = attribute.attrelid
          JOIN pg_namespace schema ON schema.oid = table_class.relnamespace
          JOIN pg_type column_type ON column_type.oid = attribute.atttypid
          JOIN pg_type base_type
            ON base_type.oid = COALESCE(NULLIF(column_type.typelem, 0), column_type.oid)
          WHERE attribute.attnum > 0
            AND NOT attribute.attisdropped
            AND table_class.relkind IN ('r', 'p')
            AND schema.nspname = 'public'
            AND (
              base_type.typname IN (#{text_types}, #{binary_types}, #{json_types})
              OR (base_type.typname = #{varchar} AND attribute.atttypmod = -1)
            )
          ORDER BY table_class.relname, attribute.attnum
        SQL
      end

      def check_definitions_by_table
        connection.select_all(check_constraints_sql).each_with_object({}) do |row, definitions|
          (definitions[row['table_name']] ||= []) << row['definition']
        end
      end

      def check_constraints_sql
        <<~SQL
          SELECT
            table_class.relname AS table_name,
            pg_get_constraintdef(constraint_catalog.oid) AS definition
          FROM pg_constraint constraint_catalog
          JOIN pg_class table_class ON table_class.oid = constraint_catalog.conrelid
          JOIN pg_namespace schema ON schema.oid = table_class.relnamespace
          WHERE constraint_catalog.contype = 'c'
            AND schema.nspname = 'public'
        SQL
      end

      def quote_type_names(type_names)
        type_names.map { |type_name| connection.quote(type_name) }.join(', ')
      end
    end
  end
end
