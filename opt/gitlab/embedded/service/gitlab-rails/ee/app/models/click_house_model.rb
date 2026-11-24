# frozen_string_literal: true

module ClickHouseModel
  extend ActiveSupport::Concern

  included do
    class << self
      attr_accessor :clickhouse_table_name
    end
  end

  def store_to_clickhouse
    return false unless valid?

    ::ClickHouse::WriteBuffer.add(self.class.clickhouse_table_name, to_clickhouse_csv_row)
  end

  def to_clickhouse_csv_row
    raise NoMethodError # must be overloaded in descendants
  end
end
