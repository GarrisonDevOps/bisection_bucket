# frozen_string_literal: true

module Gitlab
  module SecurityReportSchemas
    module Utils
      # Contains utility methods for the String class
      module StringRefinements
        refine String do
          def red
            "\e[31m#{self}\e[0m"
          end

          def green
            "\e[32m#{self}\e[0m"
          end

          def brown
            "\e[33m#{self}\e[0m"
          end
        end
      end
    end
  end
end
