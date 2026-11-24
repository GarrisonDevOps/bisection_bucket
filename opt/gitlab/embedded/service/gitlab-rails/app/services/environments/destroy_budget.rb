# frozen_string_literal: true

module Environments
  # Bounds the rows and time one batched environment delete spends
  class DestroyBudget
    MAX_ROWS = 20_000
    MAX_RUNTIME = 20.seconds

    def initialize(user:, max_rows: MAX_ROWS, max_runtime: MAX_RUNTIME)
      @user = user
      @max_rows = [max_rows, user_rows_limit].compact.min
      @runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(max_runtime)
      @deleted_count = 0
    end

    # The rows limit stops the next batch, so a request that deleted the last rows still deletes the environment
    def stop_reason(batch_size:)
      return :throttled if throttled?

      :incomplete if next_batch_over_max_rows?(batch_size) || @runtime_limiter.over_time?
    end

    def charge(row_count)
      @deleted_count += row_count
      @throttled = row_count > 0 && rows_throttled?(cost: row_count)
    end

    private

    # The rows limit never stops the first batch, so a limit below the batch size still lets each request make progress
    def next_batch_over_max_rows?(batch_size)
      @deleted_count > 0 && @deleted_count + batch_size > @max_rows
    end

    def user_rows_limit
      return unless @user

      limit = ::Gitlab::ApplicationRateLimiter.enforced_limit_for(:environment_delete_rows, scope: { user: @user })
      limit if limit > 0
    end

    def throttled?
      @throttled = rows_throttled?(peek: true) if @throttled.nil?
      @throttled
    end

    def rows_throttled?(peek: false, cost: nil)
      return false unless @user

      ::Gitlab::ApplicationRateLimiter.throttled?(
        :environment_delete_rows, scope: { user: @user }, peek: peek, cost: cost
      )
    end
  end
end
