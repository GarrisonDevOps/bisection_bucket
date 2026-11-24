# frozen_string_literal: true

module ClickHouse
  module Client
    class ArelEngine
      def quote_table_name(name)
        "`#{name}`" # Safest approach for ClickHouse
      end

      def quote_column_name(name)
        quote_table_name(name)
      end

      def quote(value)
        ClickHouse::Client::Quoting.quote(value)
      end
    end
  end
end
