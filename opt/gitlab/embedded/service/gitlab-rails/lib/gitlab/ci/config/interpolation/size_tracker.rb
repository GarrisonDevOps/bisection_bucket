# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module Interpolation
        class SizeTracker
          FAILURE_MULTIPLIER = 10

          attr_reader :total_bytes

          def initialize(project_id: nil)
            @project_id = project_id
            @max_bytes = Gitlab::CurrentSettings.current_application_settings.max_yaml_size_bytes
            @total_bytes = 0
            @logged = false
            @logged_failure = false
            @logged_rejection = false
          end

          def fits?(bytes)
            total_bytes + bytes <= failure_bytes
          end

          def add(bytes)
            @total_bytes += bytes

            log_above_limit if !@logged && total_bytes > max_bytes
            log_above_failure_limit if !@logged_failure && total_bytes > failure_bytes
          end

          def reject(bytes)
            return if @logged_rejection

            @logged_rejection = true

            log('CI config interpolation was stopped at the failure limit',
              failure_limit_bytes: failure_bytes, rejected_bytes: bytes)
          end

          private

          attr_reader :max_bytes, :project_id

          def failure_bytes
            max_bytes * FAILURE_MULTIPLIER
          end

          def log_above_limit
            @logged = true

            log('CI config interpolation result is larger than max_yaml_size_bytes')
          end

          def log_above_failure_limit
            @logged_failure = true

            log('CI config interpolation result is larger than the failure limit', failure_limit_bytes: failure_bytes)
          end

          def log(message, **details)
            Gitlab::AppJsonLogger.info(
              Labkit::Fields::CLASS_NAME => self.class.name,
              message: message,
              Labkit::Fields::GL_PROJECT_ID => project_id,
              total_bytes: total_bytes,
              max_yaml_size_bytes: max_bytes,
              **details
            )
          end
        end
      end
    end
  end
end
