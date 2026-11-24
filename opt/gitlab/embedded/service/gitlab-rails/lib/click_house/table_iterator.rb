# frozen_string_literal: true

module ClickHouse
  # Iterates over a MergeTree table in primary key ranges. Range boundaries are derived from the
  # granule index (`mergeTreeIndex`) with a single query, so it works for composite and
  # non-numeric primary keys too.
  #
  # Usage:
  #
  # connection = ClickHouse::Connection.new(:main)
  # iterator = ClickHouse::TableIterator.new('events', primary_keys: %i[project_id id], connection: connection)
  # iterator.each_range(of: 10_000) do |scope, min_keys, max_keys|
  #   ClickHouse::Client.select(scope, :main)
  # end
  #
  # Ranges are half-open: min_keys is inclusive, max_keys is exclusive. The first range starts at
  # the smallest key and the last range ends at the largest key, inclusive, so every range is
  # bounded. Rows inserted during the iteration are not guaranteed to be visited.
  #
  # Filtering is not supported: the ranges are computed over the whole table.
  #
  # Requirements:
  # - the table must be a *MergeTree table (mergeTreeIndex rejects anything else)
  # - primary_keys must be the PRIMARY KEY columns in order
  # - DateTime and DateTime64 primary key columns must use the UTC timezone
  class TableIterator
    # rubocop: disable CodeReuse/ActiveRecord -- this is a ClickHouse query builder class using Arel

    # mergeTreeIndex gives one row per granule (PK columns = the granule's first key), so a
    # running total of rows in key order yields the key at every batch_size-th row.
    #   - Batch on the granule's start offset (rows before the granule), so a granule straddling an
    #     edge stays with the batch it starts in.
    #   - tuple() is mandatory: `(c1)` is just a parenthesised c1 for a single-column PK.
    #   - rows_in_granule > 0 drops each part's zero-row "final mark".
    #   - Granules and boundaries are limited to the edge keys, so rows inserted after the edge keys
    #     were read can't produce a boundary outside of them.
    #   - Aliases are prefixed with `bti__` so they can't clash with primary key column names.
    # Batch sizes are approximate: a batch can overshoot by index_granularity x overlapping parts.
    BOUNDARIES_QUERY = <<~SQL
      SELECT DISTINCT %{key_columns}
      FROM (
        SELECT intDiv(bti__rows_before_granule, {batch_size:UInt64}) AS bti__batch_number,
               min(bti__granule_start_key) AS bti__key
        FROM (
          SELECT %{key_tuple} AS bti__granule_start_key,
                 sum(rows_in_granule) OVER (
                   ORDER BY %{key_tuple} ASC
                   ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
                 ) AS bti__rows_before_granule
          FROM mergeTreeIndex({database:String}, {table:String}, with_marks = false)
          WHERE rows_in_granule > 0
            AND bti__granule_start_key >= %{min_key}
            AND bti__granule_start_key <= %{max_key}
        )
        GROUP BY bti__batch_number
      )
      WHERE bti__key > %{min_key} AND bti__key < %{max_key}
      ORDER BY bti__key ASC
    SQL

    # The granule index holds only each granule's first key, with trailing PK columns possibly
    # replaced by defaults, so the edge keys need a real read. Reading in order makes this touch
    # only the first or last granule of each part.
    EDGE_KEY_QUERY = <<~SQL
      SELECT %{key_columns}
      FROM (
        SELECT %{key_tuple} AS bti__key
        FROM %{table}
        ORDER BY %{order_by}
        LIMIT 1
      )
    SQL

    Boundary = Struct.new(:typed_values, :raw_values, :types)
    private_constant :Boundary

    def initialize(table, primary_keys:, connection:)
      raise ArgumentError, 'primary_keys must not be empty' if primary_keys.blank?

      @table = table.to_s
      @primary_keys = primary_keys.map(&:to_s)
      @connection = connection
    end

    def each_range(of: 10_000)
      return enum_for(:each_range, of: of) unless block_given?

      raise ArgumentError, "batch size must be positive, got #{of}" unless of.to_i > 0

      min_key = find_edge_key(:asc)
      max_key = find_edge_key(:desc)
      return unless min_key && max_key

      validate_key_types!(min_key)

      edges = [min_key, *find_boundaries(of.to_i, min_key, max_key), max_key]

      edges.each_cons(2).with_index do |(min_boundary, max_boundary), i|
        last = i == edges.size - 2

        yield scope_for(min_boundary, max_boundary, max_inclusive: last),
          keys_hash(min_boundary),
          keys_hash(max_boundary)
      end
    end

    private

    attr_reader :table, :primary_keys, :connection

    # Boundaries round-trip through toString, which drops the UTC offset. In a DST timezone the
    # repeated hour becomes ambiguous and shifts boundaries by an hour.
    def validate_key_types!(boundary)
      primary_keys.zip(boundary.types).each do |key, type|
        next unless type.start_with?('DateTime') && type.exclude?("'UTC'")

        raise ArgumentError, "primary key column #{key} must use the UTC timezone, got #{type}"
      end
    end

    def find_boundaries(batch_size, min_key, max_key)
      raw_query = format(BOUNDARIES_QUERY, key_columns: key_columns, key_tuple: key_tuple,
        min_key: boundary_tuple(min_key), max_key: boundary_tuple(max_key))

      query = ClickHouse::Client::Query.new(
        raw_query: raw_query,
        placeholders: { batch_size: batch_size, database: connection.database_name, table: table }
      )

      connection.select(query).map { |row| build_boundary(row) }
    end

    def find_edge_key(direction)
      order_by = primary_keys.map { |key| "#{quote_identifier(key)} #{direction.to_s.upcase}" }.join(', ')
      raw_query = format(EDGE_KEY_QUERY, key_columns: key_columns, key_tuple: key_tuple,
        table: quote_identifier(table), order_by: order_by)

      row = connection.select(raw_query).first
      build_boundary(row) if row
    end

    def key_tuple
      "tuple(#{primary_keys.map { |key| quote_identifier(key) }.join(', ')})"
    end

    def key_columns
      primary_keys.each_index.flat_map do |i|
        element = "tupleElement(bti__key, #{i + 1})"
        ["#{element} AS c#{i}", "toString(#{element}) AS c#{i}_str", "toTypeName(#{element}) AS c#{i}_type"]
      end.join(', ')
    end

    def boundary_tuple(boundary)
      values = boundary.raw_values.zip(boundary.types).map do |raw_value, type|
        "CAST(#{ClickHouse::Client::Quoting.quote(raw_value)}, #{ClickHouse::Client::Quoting.quote(type)})"
      end

      "tuple(#{values.join(', ')})"
    end

    def build_boundary(row)
      Boundary.new(
        primary_keys.each_index.map { |i| row["c#{i}"] },
        primary_keys.each_index.map { |i| row["c#{i}_str"] },
        primary_keys.each_index.map { |i| row["c#{i}_type"] }
      )
    end

    def scope_for(min_boundary, max_boundary, max_inclusive:)
      scope = ClickHouse::Client::QueryBuilder.new(table)
      # Strict at every position, because the upper bound is the next range's lower bound. An
      # inclusive end only relaxes the final position.
      final_node = max_inclusive ? Arel::Nodes::LessThanOrEqual : Arel::Nodes::LessThan

      scope
        .where(tuple_compare(scope, min_boundary, Arel::Nodes::GreaterThan, Arel::Nodes::GreaterThanOrEqual))
        .where(tuple_compare(scope, max_boundary, Arel::Nodes::LessThan, final_node))
    end

    # Expands a lexicographic tuple comparison into an OR of ANDs so ClickHouse can use the
    # primary key index (it doesn't prune through the native tuple form). For (c1, c2) >= (v1, v2):
    #   (c1 > v1) OR (c1 = v1 AND c2 >= v2)
    # Values are CAST from their ClickHouse string form to avoid precision loss in Ruby.
    def tuple_compare(scope, boundary, prefix_node, final_node)
      values = boundary.raw_values.zip(boundary.types).map do |raw_value, type|
        Arel::Nodes::NamedFunction.new('CAST', [Arel::Nodes.build_quoted(raw_value), Arel::Nodes.build_quoted(type)])
      end

      conditions = primary_keys.each_index.map do |i|
        node = i == primary_keys.size - 1 ? final_node : prefix_node
        equalities = (0...i).map { |j| scope.table[primary_keys[j]].eq(values[j]) }

        (equalities + [node.new(scope.table[primary_keys[i]], values[i])]).reduce(:and)
      end

      conditions.reduce(:or)
    end

    def keys_hash(boundary)
      primary_keys.map(&:to_sym).zip(boundary.typed_values).to_h
    end

    def quote_identifier(name)
      "`#{name.gsub('`', '``')}`"
    end

    # rubocop: enable CodeReuse/ActiveRecord
  end
end
