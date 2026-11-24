# frozen_string_literal: true

module Gitlab
  module Geo
    class Logger < ::Gitlab::JsonLogger
      exclude_context!

      module StdoutLogger
        def full_log_path
          $stdout
        end
      end

      def self.file_name_noext
        'geo'
      end
    end
  end
end
