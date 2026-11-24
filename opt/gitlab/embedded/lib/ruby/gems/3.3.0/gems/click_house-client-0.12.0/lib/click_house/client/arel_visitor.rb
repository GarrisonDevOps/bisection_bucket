# frozen_string_literal: true

require 'active_record'

module ClickHouse
  module Client
    class ArelVisitor < Arel::Visitors::ToSql
      private

      # rubocop:disable Naming/MethodName -- parent method calls in this format
      def visit_Arel_Nodes_Matches(object, collector)
        op = object.case_sensitive ? " LIKE " : " ILIKE "
        collector = infix_value object, collector, op
        if object.escape
          collector << " ESCAPE "
          visit object.escape, collector
        else
          collector
        end
      end

      def visit_Arel_Nodes_DoesNotMatch(object, collector)
        op = object.case_sensitive ? " NOT LIKE " : " NOT ILIKE "
        collector = infix_value object, collector, op
        if object.escape
          collector << " ESCAPE "
          visit object.escape, collector
        else
          collector
        end
      end

      # ClickHouse rejects a bare `UNION`; the mode must be explicit.
      def visit_Arel_Nodes_Union(object, collector)
        infix_value_with_paren(object, collector, " UNION DISTINCT ")
      end

      def visit_ClickHouse_Client_ArelExtensions_Nodes_Final(object, collector)
        collector = visit(object.expr, collector)
        collector << " FINAL"
      end

      # rubocop:enable Naming/MethodName
    end
  end
end
