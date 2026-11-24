# frozen_string_literal: true

module Gitlab
  module Database
    # Reads the SQL runtime Active Record accumulates for the current thread or
    # fiber, in milliseconds. Rails 8.1 moved these counters off
    # ActiveRecord::RuntimeRegistry itself and onto RuntimeRegistry.stats.
    module SqlRuntime
      def self.total_ms
        if ::ActiveRecord.gem_version >= Gem::Version.new('8.1')
          ::ActiveRecord::RuntimeRegistry.stats.sql_runtime
        else
          ::ActiveRecord::RuntimeRegistry.sql_runtime
        end
      end
    end
  end
end
