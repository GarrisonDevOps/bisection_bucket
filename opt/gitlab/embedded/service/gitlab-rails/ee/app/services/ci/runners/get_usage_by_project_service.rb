# frozen_string_literal: true

module Ci
  module Runners
    class GetUsageByProjectService < GetUsageServiceBase
      extend ::Gitlab::Utils::Override

      private

      override :table_name
      def table_name
        'ci_used_minutes'
      end

      override :bucket_column
      def bucket_column
        'project_id'
      end
    end
  end
end
