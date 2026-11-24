# frozen_string_literal: true

module Quality
  # Reports which value classes each column's seeded rows actually cover. Where FixtureCoverage
  # answers "is this column ever null", this answers "does a later migration have every shape it
  # could trip on" - an empty string, multibyte text, a negative number.
  class ValueClassCoverage
    # The classes worth covering per column type, as SQL predicates. Deliberately hand-written
    # rather than derived: what breaks a migration is decided by people, not inferred from data.
    RULES = {
      string: {
        'empty' => "%{column} = ''",
        'ascii' => "%{column} <> '' AND octet_length(%{column}) = char_length(%{column})",
        'glyphs' => 'octet_length(%{column}) <> char_length(%{column})'
      },
      integer: {
        'zero' => '%{column} = 0',
        'positive' => '%{column} > 0',
        'negative' => '%{column} < 0'
      },
      boolean: {
        'true' => '%{column} IS TRUE',
        'false' => '%{column} IS FALSE'
      },
      # Cast so the same predicates hold for a `json` column, which has no equality operator
      # against `jsonb`.
      jsonb: {
        'empty' => "%{column}::jsonb IN ('{}'::jsonb, '[]'::jsonb)",
        'populated' => "%{column}::jsonb NOT IN ('{}'::jsonb, '[]'::jsonb)"
      },
      datetime: {
        'present' => '%{column} IS NOT NULL'
      },
      array: {
        'empty' => 'cardinality(%{column}) = 0',
        'populated' => 'cardinality(%{column}) > 0'
      },
      # A key never holds zero or a negative, so the only shape worth varying is whether it is set.
      identifier: {
        'present' => '%{column} IS NOT NULL'
      }
    }.freeze

    # Rails reports these as distinct types but they share a rule set.
    TYPE_ALIASES = {
      text: :string,
      bigint: :integer,
      json: :jsonb,
      date: :datetime,
      timestamptz: :datetime
    }.freeze

    INTEGER_TYPES = %i[integer bigint].freeze

    NULL_CLASS = 'null'

    # A check constraint can put a class out of reach even when the column's type allows it, as
    # `add_not_null_constraint` does by leaving `attnotnull` unset. Anchored so a compound
    # expression, which may still permit the value, never matches.
    FORBIDDEN_BY_CHECK = {
      'null' => /\A\(?(\w+) IS NOT NULL\)?\z/,
      'negative' => /\A\(?(\w+) >=? 0\)?\z/,
      'zero' => /\A\(?(\w+) > 0\)?\z/
    }.freeze

    Finding = Struct.new(:table, :column, :type, :seeded, :covered, :missing, keyword_init: true) do
      def complete?
        missing.empty?
      end

      # Nothing is covered yet, so the classes read as a specification for the fixture to write
      # rather than as a gap in one that exists.
      def unseeded?
        !seeded
      end

      def summary
        return "#{column} (#{type}): needs #{missing.join(', ')}" if unseeded?
        return "#{column} (#{type}): covers #{covered.join(', ')}" if complete?

        "#{column} (#{type}): missing #{missing.join(', ')} (covers #{covered.join(', ')})"
      end
    end

    def initialize(tables, connection:)
      @tables = tables
      @connection = connection
    end

    def findings
      tables.flat_map do |table|
        connection.table_exists?(table) ? examine(table) : []
      end
    end

    private

    attr_reader :tables, :connection

    def examine(table)
      checks = checks_for(table, connection.primary_key(table))
      return [] if checks.empty?

      counts = count_classes(table, checks)
      seeded = counts.fetch('row_count').to_i > 0

      checks.group_by { |check| check[:column] }.map do |column, column_checks|
        present, absent = column_checks.partition { |check| counts[check[:alias]].to_i > 0 }

        Finding.new(
          table: table, column: column.name, type: column.type, seeded: seeded,
          covered: present.map { |check| check[:class_name] },
          missing: absent.map { |check| check[:class_name] }
        )
      end
    end

    # A NOT NULL column can never hold a null, so offering it as a missing class would report a
    # gap nobody can close.
    def checks_for(table, primary_key)
      forbidden = forbidden_classes(table)

      checks = connection.columns(table).flat_map do |column|
        rules = RULES[rule_key(column, primary_key)]
        next [] unless rules

        classes = column.null ? { NULL_CLASS => '%{column} IS NULL' }.merge(rules) : rules
        classes
          .reject { |class_name, _| forbidden[column.name].include?(class_name) }
          .map { |class_name, predicate| build_check(column, class_name, predicate) }
      end

      # Postgres truncates identifiers at 63 bytes, so an alias built from a long column name
      # could collide with another class on the same column and read back the wrong count.
      checks.each_with_index { |check, index| check[:alias] = "c#{index}" }
    end

    # A `NOT VALID` constraint still rejects new rows, so it counts here too.
    def forbidden_classes(table)
      empty = Hash.new { |hash, key| hash[key] = Set.new }

      connection.check_constraints(table).each_with_object(empty) do |constraint, forbidden|
        # Postgres quotes a column name that collides with a keyword, as `position` does, and a
        # double quote there can only ever be an identifier quote.
        expression = constraint.expression.to_s.delete('"')

        FORBIDDEN_BY_CHECK.each do |class_name, pattern|
          column = expression[pattern, 1]
          forbidden[column] << class_name if column
        end
      end
    end

    # Rails reports an array column by its element type, so `bigint[]` arrives as :integer and
    # would otherwise be compared against a scalar. Only integer keys are identifiers: a `*_id`
    # holding a commit SHA is text, and its empty and multibyte shapes still matter.
    def rule_key(column, primary_key)
      return :array if column.array?
      return TYPE_ALIASES.fetch(column.type, column.type) unless INTEGER_TYPES.include?(column.type)
      return :identifier if Array(primary_key).include?(column.name) || column.name.end_with?('_id')

      :integer
    end

    def build_check(column, class_name, predicate)
      {
        column: column,
        class_name: class_name,
        predicate: format(predicate, column: connection.quote_column_name(column.name))
      }
    end

    def count_classes(table, checks)
      selects = ['count(*) AS row_count']
      checks.each do |check|
        selects << "count(*) FILTER (WHERE #{check[:predicate]}) AS #{connection.quote_column_name(check[:alias])}"
      end

      connection.select_one("SELECT #{selects.join(', ')} FROM #{connection.quote_table_name(table)}")
    end
  end
end
