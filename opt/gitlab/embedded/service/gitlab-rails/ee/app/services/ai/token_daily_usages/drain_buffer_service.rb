# frozen_string_literal: true

module Ai
  module TokenDailyUsages
    class DrainBufferService
      MAX_RUNTIME = 200.seconds

      def execute
        runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
        inserted_rows = 0
        dropped_rows = 0

        status = loop do
          payload = FlushBufferService.new.execute.payload
          dropped_rows += payload[:dropped_rows]
          break :processed if payload[:inserted_rows] == 0 && payload[:dropped_rows] == 0

          inserted_rows += payload[:inserted_rows]
          break :over_time if runtime_limiter.over_time?
        end

        ServiceResponse.success(payload: { status: status, inserted_rows: inserted_rows, dropped_rows: dropped_rows })
      end
    end
  end
end
