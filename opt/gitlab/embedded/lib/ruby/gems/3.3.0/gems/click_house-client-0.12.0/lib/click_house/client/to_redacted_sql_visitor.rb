# frozen_string_literal: true

module ClickHouse
  module Client
    # Redacts the SQL query represented by the query builder.
    #
    # Example:
    #   query_builder = ClickHouse::QueryBuilder.new('users').where(name: 'John Doe')
    #   redacted_query = query_builder.to_redacted_sql
    #   # The redacted_query will contain the SQL query with values replaced by placeholders.
    #   output: "SELECT * FROM \"users\" WHERE \"users\".\"name\" = ?"
    class ToRedactedSqlVisitor < ArelVisitor
      private

      def redaction_enabled?
        !!@redaction_enabled
      end

      def collect_nodes_for(nodes, collector, spacer, *args)
        return super unless spacer.strip.in?(%w[WHERE HAVING])

        redaction_was = @redaction_enabled
        @redaction_enabled = true
        super
        @redaction_enabled = redaction_was
      end

      # rubocop:disable Naming/MethodName -- following Arel::Visitors::Visitor pattern
      # rubocop:disable Naming/MethodParameterName -- following Arel::Visitors::Visitor pattern

      def visit_Arel_Nodes_In(o, collector)
        return super unless redaction_enabled?

        return super if o.right.is_a? Arel::Nodes::SelectStatement

        super(redact_right(o), collector)
      end

      def visit_Arel_Nodes_Equality(o, collector)
        return super unless redaction_enabled?

        super(redact_right(o), collector)
      end

      def visit_Arel_Nodes_LessThan(o, collector)
        return super unless redaction_enabled?

        super(redact_right(o), collector)
      end

      def visit_Arel_Nodes_LessThanOrEqual(o, collector)
        return super unless redaction_enabled?

        super(redact_right(o), collector)
      end

      def visit_Arel_Nodes_GreaterThan(o, collector)
        return super unless redaction_enabled?

        super(redact_right(o), collector)
      end

      def visit_Arel_Nodes_GreaterThanOrEqual(o, collector)
        return super unless redaction_enabled?

        super(redact_right(o), collector)
      end

      def visit_Arel_Nodes_NamedFunction(o, collector)
        return super unless redaction_enabled?

        redacted_o = Arel::Nodes::NamedFunction.new(o.name, o.expressions.dup)

        case redacted_o.name
        when 'startsWith'
          redacted_o.expressions[1] = bind_param
        else
          redacted_o.expressions = redacted_o.expressions.map { bind_param }
        end

        super(redacted_o, collector)
      end

      def visit_Arel_Nodes_Matches(o, collector)
        return super unless redaction_enabled?

        super(redact_right(o), collector)
      end

      def redact_right(o)
        cloned_o = o.clone

        redacted_right = if o.right.is_a?(Array)
                           Array.new(o.right.size) { bind_param }
                         else
                           bind_param
                         end

        cloned_o.right = redacted_right
        cloned_o
      end

      def bind_param
        Arel::Nodes::BindParam.new('?')
      end

      # rubocop:enable Naming/MethodName
      # rubocop:enable Naming/MethodParameterName
    end
  end
end
