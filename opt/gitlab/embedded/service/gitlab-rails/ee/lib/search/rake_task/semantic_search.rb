# frozen_string_literal: true

module Search
  module RakeTask
    module SemanticSearch
      class << self
        def info(name: nil, watch_interval: nil)
          run_with_interval(name: name, watch_interval: watch_interval) do
            task_executor_service.execute(:info)
          end
        end

        private

        def task_executor_service
          Search::SemanticSearch::RakeTaskExecutorService.new(logger: stdout_logger)
        end

        def run_with_interval(name:, watch_interval:)
          interval = watch_interval.to_f
          return yield if interval <= 0

          loop do
            clear_screen

            stdout_logger.info "Every #{interval}s: #{name} (Updated: #{Time.now.utc.iso8601})"
            yield
            sleep interval
          end
        rescue Interrupt
          puts "\nInterrupted. Exiting gracefully..."
        end

        def clear_screen
          system('clear') || system('cls')
        end

        def stdout_logger
          @stdout_logger ||= Logger.new($stdout).tap do |logger|
            logger.formatter = ->(_severity, _datetime, _progname, msg) { "#{msg}\n" }
          end
        end
      end
    end
  end
end
