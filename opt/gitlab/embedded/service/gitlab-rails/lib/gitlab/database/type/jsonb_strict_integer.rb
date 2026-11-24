# frozen_string_literal: true

module Gitlab
  module Database
    module Type
      # Casts only whole numbers; everything else is kept as given so a
      # validation can reject it. The lenient JsonbInteger turns 9.5 into 9.
      class JsonbStrictInteger < ActiveModel::Type::Value
        def cast(value)
          return value if value.nil? || value.is_a?(Integer)
          return if value.is_a?(String) && value.strip.empty?

          Integer(value.to_s, 10, exception: false) || value
        end
      end
    end
  end
end
