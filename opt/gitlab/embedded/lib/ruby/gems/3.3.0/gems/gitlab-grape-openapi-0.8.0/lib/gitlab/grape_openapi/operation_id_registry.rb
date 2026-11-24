# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    class OperationIdRegistry
      def initialize
        @operation_ids = {}
      end

      def register(candidate)
        operation_id = candidate
        suffix = 2

        while @operation_ids.key?(operation_id)
          operation_id = "#{candidate}_#{suffix}"
          suffix += 1
        end

        @operation_ids[operation_id] = true
        operation_id
      end
    end
  end
end
