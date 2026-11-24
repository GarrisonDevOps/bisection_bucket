# frozen_string_literal: true

require 'json'

module Gitlab
  module SecretDetection
    module Core
      # Finding is a data object representing a secret finding identified within a payload
      class Finding
        attr_reader :payload_id, :status, :line_number, :type, :description, :raw_value

        def initialize(payload_id, status, line_number = nil, type = nil, description = nil, raw_value: nil)
          @payload_id = payload_id
          @status = status
          @line_number = line_number
          @type = type
          @description = description
          @raw_value = raw_value
        end

        def ==(other)
          self.class == other.class && other.state == state
        end

        # +raw_value+ is omitted here, and from +state+ and +inspect+, so a secret cannot leak.
        def to_h
          {
            payload_id:,
            status:,
            line_number:,
            type:,
            description:
          }
        end

        def as_json(_options = nil)
          to_h
        end

        def to_json(*args)
          to_h.to_json(*args)
        end

        # The default +inspect+ would dump +raw_value+ in plain text, reaching `p`, error contexts,
        # and anything holding a Finding (+Response+ included).
        def inspect
          "#<#{self.class.name} payload_id=#{payload_id.inspect} status=#{status.inspect} " \
            "line_number=#{line_number.inspect} type=#{type.inspect} " \
            "description=#{description.inspect} raw_value=#{raw_value.nil? ? 'nil' : '[FILTERED]'}>"
        end

        protected

        def state
          [payload_id, status, line_number, type, description]
        end
      end
    end
  end
end
