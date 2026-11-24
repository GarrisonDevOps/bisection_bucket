# frozen_string_literal: true

require 'active_record'
require_relative 'arel_extensions/nodes/final'

module ClickHouse
  module Client
    class QueryBuilder < QueryLike
      attr_reader :table
      attr_accessor :manager

      VALID_NODES = [
        Arel::Nodes::In,
        Arel::Nodes::Equality,
        Arel::Nodes::LessThan,
        Arel::Nodes::LessThanOrEqual,
        Arel::Nodes::GreaterThan,
        Arel::Nodes::GreaterThanOrEqual,
        Arel::Nodes::NamedFunction,
        Arel::Nodes::NotIn,
        Arel::Nodes::NotEqual,
        Arel::Nodes::Between,
        Arel::Nodes::And,
        Arel::Nodes::Or,
        Arel::Nodes::Grouping,
        Arel::Nodes::Matches,
        Arel::Nodes::DoesNotMatch,
        Arel::Nodes::Division,
        Arel::Nodes::Multiplication,
        Arel::Nodes::As
      ].freeze

      delegate :[], to: :table

      def initialize(table, alias_name = nil)
        @table = case table
                 when self.class # subquery
                   Arel::Nodes::TableAlias.new(table.to_arel, alias_name)
                 when Arel::Nodes::TableAlias
                   table
                 else
                   Arel::Table.new(table)
                 end

        @manager = Arel::SelectManager.new(Arel::Table.engine).from(@table).project(Arel.star)
      end

      def initialize_copy(other)
        super

        @manager = other.manager.clone
      end

      # The `where` method currently only supports IN and equal to queries along
      # with above listed VALID_NODES.
      # For example, using a range (start_date..end_date) will result in incorrect SQL.
      # If you need to query a range, use greater than and less than constraints with Arel.
      #
      # Correct usage:
      #   query.where(query.table[:created_at].lteq(Date.today)).to_sql
      #   "SELECT * FROM \"table\" WHERE \"table\".\"created_at\" <= '2023-08-01'"
      #
      # This also supports array constraints which will result in an IN query.
      #   query.where(entity_id: [1,2,3]).to_sql
      #   "SELECT * FROM \"table\" WHERE \"table\".\"entity_id\" IN (1, 2, 3)"
      #
      # Range support and more `Arel::Nodes` could be considered for future iterations.
      # @return [ClickHouse::QueryBuilder] New instance of query builder.
      def where(constraints)
        validate_constraint_type!(constraints)

        clone.tap do |new_instance|
          apply_constraints(new_instance, constraints, :where)
        end
      end

      # Evaluates given block in scope of current builder. Example:
      # query = ClickHouse::Client::QueryBuilder.new('test_table').build do
      #   select(named_func('argMax', [table[:id], table[:timestamp]]).as('max_id')).limit(10)
      # end
      # @return [ClickHouse::QueryBuilder] New instance of query builder.
      def build(&)
        instance_eval(&)
      end

      # The `having` method applies constraints to the HAVING clause, similar to how
      # `where` applies constraints to the WHERE clause. It supports the same constraint types.
      # Correct usage:
      #   query.group(:name).having(count: 5).to_sql
      #   "SELECT * FROM \"table\" GROUP BY \"table\".\"name\" HAVING \"table\".\"count\" = 5"
      #
      #   query.group(:name).having(query.table[:count].gt(10)).to_sql
      #   "SELECT * FROM \"table\" GROUP BY \"table\".\"name\" HAVING \"table\".\"count\" > 10"
      #
      # @return [ClickHouse::QueryBuilder] New instance of query builder.
      def having(constraints)
        validate_constraint_type!(constraints)

        clone.tap do |new_instance|
          apply_constraints(new_instance, constraints, :having)
        end
      end

      def select(*fields)
        clone.tap do |new_instance|
          existing_fields = new_instance.manager.projections.filter_map do |projection|
            if projection.respond_to?(:to_s) && projection.to_s == '*'
              nil
            elsif projection.is_a?(Arel::Attributes::Attribute)
              projection.name.to_s
            elsif projection.is_a?(Arel::Expressions)
              projection
            end
          end

          new_projections = (existing_fields + fields).map do |field|
            if field.is_a?(Symbol)
              field.to_s
            else
              field
            end
          end

          new_instance.manager.projections = new_projections.uniq.map do |field|
            if field.is_a?(Arel::Expressions)
              field
            else
              new_instance.table[field.to_s]
            end
          end
        end
      end

      def order(field, direction = :asc)
        validate_order_direction!(direction)

        clone.tap do |new_instance|
          order_node = case field
                       when Arel::Nodes::SqlLiteral, Arel::Nodes::Node, Arel::Attribute
                         field
                       else
                         new_instance.table[field]
                       end

          new_order = direction.to_s.casecmp('desc').zero? ? order_node.desc : order_node.asc
          new_instance.manager.order(new_order)
        end
      end

      # Inverts the direction of all ORDER BY clauses: ASC becomes DESC and
      # vice versa.
      #
      # @example
      #   query.order(:id).reverse_order.to_sql
      #   # => "SELECT * FROM `test_table` ORDER BY `test_table`.`id` DESC"
      #
      # @raise [ArgumentError] if any ordering node has no explicit direction
      # @return [ClickHouse::Client::QueryBuilder] New instance of query builder.
      def reverse_order
        clone.tap do |new_instance|
          new_instance.manager.ast.orders = new_instance.manager.ast.orders.map do |order|
            case order
            when Arel::Nodes::Ascending
              Arel::Nodes::Descending.new(order.expr)
            when Arel::Nodes::Descending
              Arel::Nodes::Ascending.new(order.expr)
            else
              raise ArgumentError, "Cannot reverse ordering node without explicit direction: #{order.class.name}"
            end
          end
        end
      end

      def group(*columns)
        clone.tap do |new_instance|
          new_instance.manager.group(*columns)
        end
      end

      def limit(count)
        manager.take(count)
        self
      end

      def offset(count)
        manager.skip(count)
        self
      end

      # Applies the ClickHouse `FINAL` modifier to the main FROM table.
      # See https://clickhouse.com/docs/en/sql-reference/statements/select/from#final-modifier
      #
      # @example
      #   query.final.to_sql
      #   # => "SELECT * FROM `test_table` FINAL"
      #
      # Note: `FINAL` only makes sense on a ClickHouse MergeTree-family table.
      #
      # WARNING: Using `FINAL` in production code can cause excessive I/O and
      # affect ClickHouse availability. Prefer using it only in test environments
      # or behind a feature flag.
      #
      # @return [ClickHouse::Client::QueryBuilder] New instance of query builder.
      def final
        clone.tap do |new_instance|
          source = new_instance.manager.source.left
          wrapped = source.is_a?(ArelExtensions::Nodes::Final) ? source : ArelExtensions::Nodes::Final.new(source)
          new_instance.manager.from(wrapped)
        end
      end

      # Returns a query that yields no rows.
      #
      # @example
      #   query.none.to_sql
      #   # => "SELECT * FROM `test_table` WHERE 1 = 0"
      #
      # @return [ClickHouse::Client::QueryBuilder] New instance of query builder.
      def none
        clone.tap do |new_instance|
          new_instance.manager.where(
            Arel.sql('1 = 0')
          )
        end
      end

      def from(subquery, alias_name)
        clone.tap do |new_instance|
          new_from = if subquery.is_a?(self.class)
                       subquery.to_arel.as(alias_name)
                     else
                       Arel::Nodes::TableAlias.new(subquery, alias_name)
                     end

          if new_instance.manager.source.left.is_a?(ArelExtensions::Nodes::Final)
            new_from = ArelExtensions::Nodes::Final.new(new_from)
          end

          new_instance.manager.from(new_from)
        end
      end

      # Wraps this query as a CTE node with the given name, so it can be passed
      # to #with: `query_builder.with(sub_query.as_cte(:foo))`. The name is
      # rendered as a SQL identifier, not a quoted value.
      #
      # The manager is cloned so later in-place mutations on this builder (e.g.
      # #limit or #offset) do not alter the captured CTE body.
      #
      # @param name [String, Symbol] name the CTE is referenced by
      # @return [Arel::Nodes::Cte]
      def as_cte(name)
        Arel::Nodes::Cte.new(Arel::Nodes::SqlLiteral.new(name.to_s), to_arel.clone)
      end

      # Attaches a CTE node, emitting `WITH name AS (...)` before the SELECT.
      # The CTE can then be referenced by name in FROM and IN-subquery positions,
      # which is useful when the same subquery is needed in more than one place.
      #
      # Build the node with #as_cte, for example
      # `query_builder.with(sub_query.as_cte(:foo))`.
      #
      # Chained calls accumulate: `query_builder.with(a).with(b)` emits both
      # CTEs. This differs from `Arel::SelectManager#with`, which replaces any
      # previously set CTE and would keep only `b`.
      #
      # @param cte [Arel::Nodes::Cte] a CTE node from #as_cte
      # @return [ClickHouse::Client::QueryBuilder]
      def with(cte)
        unless cte.is_a?(Arel::Nodes::Cte)
          raise ArgumentError, "expected Arel::Nodes::Cte, got #{cte.class}. " \
            'Use #as_cte(name) to create one.'
        end

        clone.tap do |new_instance|
          existing = new_instance.manager.ast.with
          all_ctes = existing ? existing.children + [cte] : [cte]
          validate_unique_cte_names!(all_ctes)
          new_instance.manager.ast.with = Arel::Nodes::With.new(all_ctes)
        end
      end

      # Combines this query with one or more other queries using UNION and
      # returns a new builder that selects from the combined result as an
      # aliased subquery, so further chaining (#where, #order, #limit, ...)
      # applies to the outer SELECT.
      #
      # @param others [Array<ClickHouse::Client::QueryBuilder>] queries to combine with
      # @param type [Symbol] :distinct or :all
      # @param alias_name [String, Symbol] alias for the union subquery
      # @return [ClickHouse::Client::QueryBuilder] New instance of query builder.
      def union(*others, type: :distinct, alias_name: 'union_subquery')
        validate_union_type!(type)
        raise ArgumentError, 'at least one query to union with is required' if others.empty?

        others.each do |other|
          raise ArgumentError, "expected #{self.class}, got #{other.class}" unless other.is_a?(self.class)
        end

        node_class = type == :all ? Arel::Nodes::UnionAll : Arel::Nodes::Union
        union_node = others.reduce(to_arel.clone.ast) do |left, other|
          node_class.new(left, other.to_arel.clone.ast)
        end

        self.class.new(Arel::Nodes::TableAlias.new(union_node, alias_name.to_s))
      end

      # Adds a JOIN clause. Pass `type: :outer` for `LEFT OUTER JOIN`.
      # To join a subquery, pre-alias it via `QueryBuilder.new(sub, 'x').table`
      # or `sub.to_arel.as('x')` and pass that.
      # @return [ClickHouse::Client::QueryBuilder] New instance of query builder.
      def joins(source, constraint = nil, type: :inner)
        validate_join_type!(type)

        clone.tap do |new_instance|
          join_target = case source
                        when Arel::Table, Arel::Nodes::TableAlias then source
                        else Arel::Table.new(source)
                        end
          join_class = type == :outer ? Arel::Nodes::OuterJoin : Arel::Nodes::InnerJoin

          join_condition = case constraint
                           when Hash
                             # Handle hash based constraints like { table1.id: table2.ref_id } or {id: :ref_id}
                             constraint_conditions = constraint.map do |left, right|
                               left_field = left.is_a?(Arel::Attributes::Attribute) ? left : new_instance.table[left]
                               right_field = right.is_a?(Arel::Attributes::Attribute) ? right : join_target[right]
                               left_field.eq(right_field)
                             end

                             constraint_conditions.reduce(&:and)
                           when Proc
                             constraint.call(new_instance.table, join_target)
                           when Arel::Nodes::Node, Arel::Nodes::SqlLiteral
                             constraint
                           end

          if join_condition
            new_instance.manager.join(join_target, join_class).on(join_condition)
          else
            new_instance.manager.join(join_target, join_class)
          end
        end
      end

      # Shortcut for `Arel::Nodes::NamedFunction.new`
      # @return [Arel::Nodes::NamedFunction]
      def named_func(*args)
        Arel::Nodes::NamedFunction.new(*args)
      end

      # Shortcut for `Arel::Nodes.build_quoted`
      # @return [Arel::Nodes::Node]
      def quote(...)
        Arel::Nodes.build_quoted(...)
      end

      alias_method :func, :named_func

      # Aggregation helper methods

      # Creates an AVG aggregate function node
      # @param column [Symbol, String, Arel::Expressions] The column to average
      # @return [Arel::Nodes::NamedFunction] The AVG function node
      # @example Basic average
      #   query.select(query.avg(:duration)).to_sql
      #   # => "SELECT avg(`table`.`duration`) FROM `table`"
      # @example Average with alias
      #   query.select(query.avg(:price).as('average_price')).to_sql
      #   # => "SELECT avg(`table`.`price`) AS average_price FROM `table`"
      def avg(column)
        column_node = normalize_operand(column)
        Arel::Nodes::NamedFunction.new('avg', [column_node])
      end

      # Creates a quantile aggregate function node
      # @param level [Float] The quantile level (e.g., 0.5 for median)
      # @param column [Symbol, String, Arel::Expressions] The column to calculate quantile for
      # @return [Arel::Nodes::NamedFunction] The quantile function node
      # @example Calculate median (50th percentile)
      #   query.select(query.quantile(0.5, :response_time)).to_sql
      #   # => "SELECT quantile(0.5)(`table`.`response_time`) FROM `table`"
      # @example Calculate 95th percentile with alias
      #   query.select(query.quantile(0.95, :latency).as('p95')).to_sql
      #   # => "SELECT quantile(0.95)(`table`.`latency`) AS p95 FROM `table`"
      def quantile(level, column)
        column_node = normalize_operand(column)
        Arel::Nodes::NamedFunction.new("quantile(#{level})", [column_node])
      end

      # Creates a COUNT aggregate function node
      # @param column [Symbol, String, Arel::Expressions, nil] The column to count, or nil for COUNT(*)
      # @return [Arel::Nodes::NamedFunction] The COUNT function node
      # @example Count all rows
      #   query.select(query.count).to_sql
      #   # => "SELECT count() FROM `table`"
      # @example Count specific column
      #   query.select(query.count(:id)).to_sql
      #   # => "SELECT count(`table`.`id`) FROM `table`"
      def count(column = nil)
        if column.nil?
          Arel::Nodes::NamedFunction.new('count', [])
        else
          column_node = normalize_operand(column)
          Arel::Nodes::NamedFunction.new('count', [column_node])
        end
      end

      # Creates a countIf aggregate function node
      # @param condition [Arel::Nodes::Node] The condition to count
      # @return [Arel::Nodes::NamedFunction] The countIf function node
      # @raise [ArgumentError] if condition is not an Arel node
      # @example Count rows matching a condition
      #   query.select(query.count_if(query.table[:status].eq('active'))).to_sql
      #   # => "SELECT countIf(`table`.`status` = 'active') FROM `table`"
      def count_if(condition)
        raise ArgumentError, "countIf requires an Arel node as condition" unless condition.is_a?(Arel::Nodes::Node)

        Arel::Nodes::NamedFunction.new('countIf', [condition])
      end

      # Creates a division node with grouping
      # @param left [Arel::Expressions, Symbol, String, Numeric] The dividend
      # @param right [Arel::Expressions, Symbol, String, Numeric] The divisor
      # @return [Arel::Nodes::Grouping] The grouped division node for proper precedence
      # @example Simple division
      #   query.select(query.division(:completed, :total)).to_sql
      #   # => "SELECT (`table`.`completed` / `table`.`total`) FROM `table`"
      # @example Calculate percentage
      #   rate = query.division(:success_count, :total_count)
      #   query.select(query.multiply(rate, 100).as('success_rate')).to_sql
      #   # => "SELECT ((`table`.`success_count` / `table`.`total_count`) * 100) AS success_rate FROM `table`"
      def division(left, right)
        left_node = normalize_operand(left)
        right_node = normalize_operand(right)

        Arel::Nodes::Grouping.new(Arel::Nodes::Division.new(left_node, right_node))
      end

      # Creates a multiplication node with grouping
      # @param left [Arel::Expressions, Symbol, String, Numeric] The left operand
      # @param right [Arel::Expressions, Symbol, String, Numeric] The right operand
      # @return [Arel::Nodes::Grouping] The grouped multiplication node for proper precedence
      # @example Multiply columns
      #   query.select(query.multiply(:quantity, :unit_price)).to_sql
      #   # => "SELECT (`table`.`quantity` * `table`.`unit_price`) FROM `table`"
      # @example Convert to percentage
      #   query.select(query.multiply(:rate, 100).as('percentage')).to_sql
      #   # => "SELECT (`table`.`rate` * 100) AS percentage FROM `table`"
      def multiply(left, right)
        left_node = normalize_operand(left)
        right_node = normalize_operand(right)

        Arel::Nodes::Grouping.new(Arel::Nodes::Multiplication.new(left_node, right_node))
      end

      # Creates an equality node
      # @param left [Arel::Expressions, Symbol, String] The left side of the comparison
      # @param right [Arel::Expressions, Symbol, String, Numeric, Boolean] The right side of the comparison
      # @return [Arel::Nodes::Equality] The equality node
      # @example Use in WHERE clause
      #   query.where(query.equality(:status, 'active')).to_sql
      #   # => "SELECT * FROM `table` WHERE `table`.`status` = 'active'"
      # @example Use with countIf
      #   query.select(query.count_if(query.equality(:type, 'premium'))).to_sql
      #   # => "SELECT countIf(`table`.`type` = 'premium') FROM `table`"
      def equality(left, right)
        left_node = normalize_operand(left)
        right_node = normalize_operand(right)
        Arel::Nodes::Equality.new(left_node, right_node)
      end

      # Creates an alias for a node
      # @param node [Arel::Nodes::Node] The node to alias
      # @param alias_name [String, Symbol] The alias name
      # @return [Arel::Nodes::As] The aliased node
      # @raise [ArgumentError] if node is not an Arel Expression
      # @example Alias an aggregate function
      #   avg_node = query.avg(:price)
      #   query.select(query.as(avg_node, 'average_price')).to_sql
      #   # => "SELECT avg(`table`.`price`) AS average_price FROM `table`"
      def as(node, alias_name)
        raise ArgumentError, "as requires an Arel node" unless node.is_a?(Arel::Expressions)

        node.as(alias_name.to_s)
      end

      def to_sql
        visitor = ClickHouse::Client::ArelVisitor.new(ClickHouse::Client::ArelEngine.new)
        visitor.accept(manager.ast, Arel::Collectors::SQLString.new).value
      end

      def to_redacted_sql
        visitor = ClickHouse::Client::ToRedactedSqlVisitor.new(ClickHouse::Client::ArelEngine.new)
        visitor.accept(manager.ast, Arel::Collectors::SQLString.new).value
      end

      def to_arel
        manager
      end

      private

      def normalize_operand(operand)
        case operand
        when Arel::Expressions
          operand
        when Symbol, String
          table[operand.to_s]
        else
          Arel::Nodes.build_quoted(operand)
        end
      end

      def validate_constraint_type!(constraint)
        return unless constraint.is_a?(Arel::Nodes::Node) && VALID_NODES.exclude?(constraint.class)

        raise ArgumentError, "Unsupported Arel node type for QueryBuilder: #{constraint.class.name}"
      end

      def apply_constraints(instance, constraints, clause_type)
        if constraints.is_a?(Arel::Nodes::Node)
          apply_constraint_node(instance, constraints, clause_type)
        else
          constraints.each do |key, value|
            if value.is_a?(Hash)
              # Handle nested hash for joined tables
              join_table = Arel::Table.new(key)
              value.each do |nested_key, nested_value|
                constraint = build_constraint(join_table, nested_key, nested_value)
                apply_constraint_node(instance, constraint, clause_type)
              end
            else
              constraint = build_constraint(instance.table, key, value)
              apply_constraint_node(instance, constraint, clause_type)
            end
          end
        end
      end

      def apply_constraint_node(instance, constraint, clause_type)
        case clause_type
        when :where
          instance.manager.where(constraint)
        when :having
          instance.manager.having(constraint)
        else
          raise ArgumentError, "Unsupported clause type: #{clause_type}"
        end
      end

      def build_constraint(table, key, value)
        if value.is_a?(Array)
          table[key].in(value)
        elsif value.is_a?(ClickHouse::Client::QueryBuilder)
          table[key].in(value.to_arel)
        else
          table[key].eq(value)
        end
      end

      def validate_order_direction!(direction)
        return if %w[asc desc].include?(direction.to_s.downcase)

        raise ArgumentError, "Invalid order direction '#{direction}'. Must be :asc or :desc"
      end

      def validate_union_type!(type)
        return if %i[distinct all].include?(type)

        raise ArgumentError, "Invalid union type '#{type}'. Must be :distinct or :all"
      end

      def validate_join_type!(type)
        return if %i[inner outer].include?(type)

        raise ArgumentError, "Invalid join type '#{type}'. Must be :inner or :outer"
      end

      def validate_unique_cte_names!(ctes)
        names = ctes.map { |cte| cte.name.to_s }
        duplicates = names.tally.select { |_, count| count > 1 }.keys

        return if duplicates.empty?

        raise ArgumentError, "duplicate CTE name(s): #{duplicates.join(', ')}"
      end
    end
  end
end
