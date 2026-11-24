# frozen_string_literal: true

module Search
  module RakeTask
    module Elastic
      class << self
        def validate_index_and_search
          task_executor_service.execute(:index_and_search_validation)
        end

        def task_executor_service
          Search::RakeTaskExecutorService.new(logger: stdout_logger)
        end

        def stdout_logger
          @stdout_logger ||= Logger.new($stdout).tap do |l|
            l.formatter = proc do |_severity, _datetime, _progname, msg|
              "#{msg}\n"
            end
          end
        end
      end
    end
  end
end
