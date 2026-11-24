# frozen_string_literal: true

module Gitlab
  module Database
    module Aggregation
      # Rejects values outside the `in:` option, adding an `:inclusion` error to the attribute with
      # the invalid values as `%{values}`. It follows the ActiveModel validator interface, so it runs
      # as `validator.validate(record)`.
      class AllowedValuesValidator < ActiveModel::EachValidator
        # `allowed` (the `in:` option) is an Array mixing String, Regexp, and
        # Gitlab::UntrustedRegexp entries, or any other container responding to `include?`
        # (for example a Range). Patterns are developer-defined; anchor them with `\A`/`\z`.
        def self.allowed?(allowed, value)
          return value.in?(allowed) unless allowed.is_a?(Array)

          allowed.any? do |entry|
            case entry
            when Regexp, ::Gitlab::UntrustedRegexp then entry.match?(value.to_s)
            else entry == value
            end
          end
        end

        def check_validity!
          raise ArgumentError, ':in is required' if options[:in].nil?
        end

        def validate_each(record, attribute, value)
          invalid = Array.wrap(value).reject { |v| self.class.allowed?(options[:in], v) }
          return if invalid.empty?

          record.errors.add(attribute, :inclusion, **options.slice(:message), values: invalid.uniq.join(', '))
        end
      end
    end
  end
end
