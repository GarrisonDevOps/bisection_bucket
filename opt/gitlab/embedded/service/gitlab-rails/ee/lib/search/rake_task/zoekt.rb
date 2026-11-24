# frozen_string_literal: true

module Search
  module RakeTask
    module Zoekt
      class << self
        def info(name:, extended: nil, watch_interval: nil)
          extended_mode = if extended.present?
                            Gitlab::Utils.to_boolean(extended)
                          else
                            !watch_interval
                          end

          options = { extended_mode: extended_mode }

          run_with_interval(name:, watch_interval:) do
            task_executor_service(options: options).execute(:info)
          end
        end

        def health(name:, watch_interval: nil)
          interval = watch_interval.to_f
          options = interval > 0 ? { watch_mode: true, watch_interval: interval.to_i } : {}

          run_with_interval(name:, watch_interval:) do
            task_executor_service(options: options).execute(:health)
          end
        end

        def index
          execute_or_abort(:index)
        end

        def disable
          execute_or_abort(:disable)
        end

        def pause_indexing
          execute_or_abort(:pause_indexing)
        end

        def resume_indexing
          execute_or_abort(:resume_indexing)
        end

        def estimate_storage
          task_executor_service.execute(:estimate_storage)
        end

        def reindex_projects
          execute_or_abort(:reindex_projects)
        end

        def reindex_failed_projects(project_ids: nil)
          execute_or_abort(:reindex_failed_projects, options: { project_ids: project_ids })
        end

        private

        def execute_or_abort(task, options: {})
          task_executor_service(options: options).execute(task) ||
            abort("Failed to #{task.to_s.humanize(capitalize: false)}")
        end

        def task_executor_service(options: {})
          Search::Zoekt::RakeTaskExecutorService.new(logger: stdout_logger, options: options)
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
          system('clear') || system('cls') # Clear screen (Linux/macOS & Windows)
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
