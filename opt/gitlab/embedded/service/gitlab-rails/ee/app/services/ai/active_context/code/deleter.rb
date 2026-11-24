# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class Deleter < IndexerBase
        def self.run!(active_context_repository)
          new(active_context_repository).run
        end

        def run
          raise Error, 'Adapter not set' unless adapter

          output, status = Gitlab::Popen.popen(command, nil, environment_variables)

          unless status == 0
            log_error(
              "Delete failed",
              status: status,
              error_details: output
            )
            raise Error, "Delete failed with status: #{status} and error: #{output}"
          end

          log_info('Delete successful', status: status)
        end

        private

        def options
          base_options.merge({ operation: 'delete' })
        end
      end
    end
  end
end
