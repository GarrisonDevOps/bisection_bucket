# frozen_string_literal: true

module Ai
  module ActiveContext
    class TaskService
      attr_reader :connection

      def initialize
        @connection = Ai::ActiveContext::Connection.active
      end

      def create_task(task_class, params: {}, depends_on: nil)
        Ai::ActiveContext::Task.create!(
          connection: connection,
          name: task_class.name,
          status: :pending,
          params: params,
          depends_on: depends_on
        )
      end

      # Creates a chain of tasks with each depending on the previous task
      # Example:
      #   create_chain(
      #     [Tasks::TaskOne, { foo: 'bar' }],
      #     [Tasks::TaskTwo],
      #     [Tasks::TaskThree]
      #   )
      def create_chain(*tasks_with_params)
        previous_task = nil

        tasks_with_params.each do |task_with_params|
          task_class, params = Array(task_with_params)
          previous_task = create_task(task_class, params: params || {}, depends_on: previous_task)
        end

        previous_task
      end
    end
  end
end
