# frozen_string_literal: true

module Gitlab
  # Resolves a date relative to today, for example 7 days ago or in 2 weeks.
  module RelativeDate
    OutOfRangeError = Class.new(StandardError)

    MAX_AMOUNT = 9999
    UNITS = { 'DAY' => :days, 'WEEK' => :weeks, 'MONTH' => :months, 'YEAR' => :years }.freeze

    # A negative amount is in the past, a positive amount is in the future and 0 is today.
    def self.to_date(amount:, unit:, zone: ::Time.zone)
      date = zone.today.advance(UNITS.fetch(unit.to_s) => amount.to_i)

      # PostgreSQL and Ruby reject dates outside this range, which would otherwise be a 500.
      raise OutOfRangeError, "Relative date #{amount} #{unit} is out of range" unless date.year.between?(1, 9999)

      date
    end
  end
end
