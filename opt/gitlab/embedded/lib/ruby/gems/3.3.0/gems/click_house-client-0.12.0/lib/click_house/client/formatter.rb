# frozen_string_literal: true

module ClickHouse
  module Client
    class Formatter
      DEFAULT = ->(value) { value }

      TYPE_CASTERS = {
        # UInt8/16/32/64, Int8/16/32/64
        /\AU?Int\d+\z/ => ->(value) { Integer(value) },
        # Float8/16/32/64
        /\AFloat\d+\z/ => ->(value) { Float(value) },
        # Date, Date32
        /\ADate\d*\z/ => ->(value) { Date.parse(value) },
        # DateTime64(0/3/6/9, 'UTC')
        /\ADateTime64\(\d+, 'UTC'\)\z/ => ->(value) { ActiveSupport::TimeZone['UTC'].parse(value) },
        "DateTime('UTC')" => ->(value) { ActiveSupport::TimeZone['UTC'].parse(value) },
        "IntervalSecond" => ->(value) { ActiveSupport::Duration.build(value.to_i) },
        "IntervalMillisecond" => ->(value) { ActiveSupport::Duration.build(value.to_i / 1000.0) }
      }.freeze

      def self.format(result, custom_typecasters = {})
        column_typecasters = result['meta'].each_with_object({}) do |column, hash|
          hash[column['name']] = build_typecaster(column, custom_typecasters)
        end

        result['data'].map do |row|
          row.each_with_object({}) do |(column, value), casted_row|
            casted_row[column] = value.nil? ? value : column_typecasters[column].call(value)
          end
        end
      end

      def self.build_typecaster(column, custom_typecasters)
        custom_caster = get_typecaster(column['type'], custom_typecasters)
        return ->(value) { custom_caster.call(column, value) } if custom_caster

        get_typecaster(column['type']) || DEFAULT
      end

      def self.get_typecaster(column_type, typecasters = TYPE_CASTERS)
        return unless column_type

        inner_type = column_type
          .sub(/\ANullable\((.+)\)\z/, '\1') # e.g Nullable(String)
          .sub(/\ALowCardinality\((.+)\)\z/, '\1') # e.g. LowCardinality(String)
          .sub(/\ASimpleAggregateFunction\(.+,\s*(.+)\)\z/, '\1') # e.g. SimpleAggregateFunction(sum, UInt64)

        typecasters.each do |key, caster|
          return caster if key.is_a?(String) ? key == inner_type : key.match?(inner_type)
        end

        nil
      end
    end
  end
end
