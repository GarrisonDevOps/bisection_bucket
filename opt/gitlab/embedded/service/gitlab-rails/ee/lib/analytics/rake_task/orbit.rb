# frozen_string_literal: true

module Analytics
  module RakeTask
    module Orbit
      class << self
        def info(name:, extended: nil, watch_interval: nil)
          extended_mode = if extended.present?
                            Gitlab::Utils.to_boolean(extended)
                          else
                            !watch_interval
                          end

          options = { extended_mode: extended_mode }

          run_with_interval(name: name, watch_interval: watch_interval) do
            info_service(options: options).execute
          end
        end

        private

        def info_service(options: {})
          Analytics::KnowledgeGraph::InfoService.new(logger: stdout_logger, options: options)
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
          @stdout_logger ||= Logger.new($stdout).tap do |l|
            l.formatter = ->(_severity, _datetime, _progname, msg) { "#{msg}\n" }
          end
        end
      end
    end
  end
end
