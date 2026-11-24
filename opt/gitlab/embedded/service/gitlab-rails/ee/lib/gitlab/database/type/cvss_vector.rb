# frozen_string_literal: true

module Gitlab
  module Database
    module Type
      class CvssVector < ActiveModel::Type::Value
        def serialize(value)
          case value
          when String
            value
          when ::CvssSuite::Cvss
            value.vector
          end
        end

        def serializable?(value)
          return true if value.nil?

          value = ::CvssSuite.new(value) unless value.is_a?(::CvssSuite::Cvss)

          value.valid?
        end

        def cast_value(value)
          return unless value
          # Rails 8.0 `insert_all` casts a value that is already cast.
          return value if value.is_a?(::CvssSuite::Cvss)

          ::CvssSuite.new(value)
        end
      end
    end
  end
end
