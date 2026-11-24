# frozen_string_literal: true

module EE
  module WorkItems
    module IterationArgumentHelpers
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      private

      def iteration_ids_from_args(args)
        args[:iteration_id].compact.map do |id|
          ::GitlabSchema.parse_gid(id, expected_type: ::Iteration).model_id
        rescue ::Gitlab::Graphql::Errors::ArgumentError
          id
        end
      end

      def iteration_cadence_ids_from_args(args)
        args[:iteration_cadence_id].compact.map do |id|
          ::GitlabSchema.parse_gid(id, expected_type: ::Iterations::Cadence).model_id
        rescue ::Gitlab::Graphql::Errors::ArgumentError
          id
        end
      end
    end
  end
end
