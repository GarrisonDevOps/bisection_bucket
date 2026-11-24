# frozen_string_literal: true

module Mutations
  module Boards
    module ScopedBoardMutation
      extend ActiveSupport::Concern

      prepended do
        argument :labels, [GraphQL::Types::String],
          required: false,
          description: copy_field_description(::Types::IssueType, :labels)

        argument :label_ids, [::Types::GlobalIDType[::Label]],
          required: false,
          description: 'IDs of labels to be added to the board.'

        validates mutually_exclusive: [:labels, :label_ids]
      end

      def resolve(**args)
        parsed_params = parse_arguments(args)

        super(**parsed_params)
      end

      private

      def parse_arguments(args = {})
        if args[:assignee_id]
          args[:assignee_id] = args[:assignee_id].model_id
        end

        if args[:milestone_id]
          args[:milestone_id] = args[:milestone_id].model_id
        end

        if args[:iteration_cadence_id]
          args[:iteration_cadence_id] = args[:iteration_cadence_id].model_id
        end

        args[:label_ids] &&= args[:label_ids].map do |label_id|
          ::GitlabSchema.parse_gid(label_id, expected_type: ::Label).model_id
        end

        # we need this because we also pass `gid://gitlab/Iteration/-4` or `gid://gitlab/Iteration/-4`
        # as `iteration_id` when we scope board to `Iteration::Predefined::Current` or `Iteration::Predefined::None`
        args[:iteration_id] = args[:iteration_id].model_id if args[:iteration_id]
        args
      end
    end
  end
end
