# frozen_string_literal: true

module CloudConnector
  module Utils
    def parse_time(time)
      Time.zone.parse(time).utc if time
    end
  end
end
