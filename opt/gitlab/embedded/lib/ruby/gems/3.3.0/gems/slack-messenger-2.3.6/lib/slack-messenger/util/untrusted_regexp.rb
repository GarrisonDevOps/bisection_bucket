# frozen_string_literal: true

# An untrusted regular expression is any regexp containing patterns sourced
# from user input.
#
# Ruby's built-in regular expression library allows patterns which complete in
# exponential time, permitting denial-of-service attacks.
#
# Not all regular expression features are available in untrusted regexes, and
# there is a strict limit on total execution time. See the RE2 documentation
# at https://github.com/google/re2/wiki/Syntax for more details.
#
# This class doesn't change any instance variables, which allows it to be frozen
# and setup in constants.
#
# This class only provides support replacing matched token with a block (like `gsub`).
module Slack
  class Messenger
    module Util
      class UntrustedRegexp
        require 're2'

        def initialize(pattern, multiline: false)
          if multiline
            pattern = "(?m)#{pattern}"
          end

          @regexp = RE2::Regexp.new(pattern, log_errors: false)
          @scan_regexp = initialize_scan_regexp

          raise RegexpError, regexp.error unless regexp.ok?
        end

        # There is no built-in replace with block support (like `gsub`).  We can accomplish
        # the same thing by parsing and rebuilding the string with the substitutions.
        def replace_gsub(text)
          new_text = +''
          remainder = text

          matched = match(remainder)

          until matched.nil? || matched.to_a.compact.empty?
            partitioned = remainder.partition(matched.to_s)
            new_text << partitioned.first
            remainder = partitioned.last

            new_text << yield(matched)

            matched = match(remainder)
          end

          new_text << remainder
        end

        def match(text)
          scan_regexp.match(text)
        end

        private

        attr_reader :regexp, :scan_regexp

        def initialize_scan_regexp
          if regexp.number_of_capturing_groups == 0
            RE2::Regexp.new('(' + regexp.source + ')')
          else
            regexp
          end
        end
      end
    end
  end
end
