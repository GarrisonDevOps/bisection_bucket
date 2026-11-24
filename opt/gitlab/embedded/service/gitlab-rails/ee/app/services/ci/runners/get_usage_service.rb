# frozen_string_literal: true

module Ci
  module Runners
    class GetUsageService < GetUsageServiceBase
      extend ::Gitlab::Utils::Override

      private

      override :table_name
      def table_name
        'ci_used_minutes_by_runner_daily'
      end

      override :bucket_column
      def bucket_column
        'runner_id'
      end
    end
  end
end
