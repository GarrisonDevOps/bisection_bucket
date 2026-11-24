# frozen_string_literal: true

module EE
  module Ci
    module RunnersFinder
      extend ::Gitlab::Utils::Override

      private

      override :allowed_sorts
      def allowed_sorts
        super + ['most_active_desc']
      end

      override :sort
      def sort(items)
        return sort_by_most_active(items) if sort_key == 'most_active_desc'

        super(items)
      end

      def sort_by_most_active(items)
        validate_sort_conditions!

        items = if group
                  items.with_top_running_builds_by_namespace_id(group.id)
                else
                  items.with_top_running_builds_of_runner_type(runner_type)
                end

        items.order_most_active_desc
      end

      def validate_sort_conditions!
        return if runner_type == :instance_type
        raise ArgumentError, 'most_active_desc can only be used on instance and group runners' unless group
        return if membership == :direct

        raise ArgumentError, 'most_active_desc is only supported on groups when membership is direct'
      end
    end
  end
end
