# frozen_string_literal: true

module EE
  module API
    module BoardsResponses
      extend ActiveSupport::Concern

      prepended do
        helpers do
          # Overrides API::BoardsResponses list_creation_params
          params :list_creation_params do
            optional :label_id, type: Integer, desc: 'ID of the label.'
            optional :milestone_id, type: Integer, desc: 'The ID of an existing milestone'
            optional :iteration_id, type: Integer, desc: 'ID of the iteration. Premium and Ultimate only.'
            optional :assignee_id, type: Integer, desc: 'ID of the user. Premium and Ultimate only.'
            optional :status_id, type: Integer, desc: 'ID of the status. Premium and Ultimate only.'
            exactly_one_of :label_id, :milestone_id, :iteration_id, :assignee_id, :status_id
          end

          params :update_params_ee do
            optional :assignee_id, type: Integer, desc: 'ID of the assignee to scope the board to. Premium and ' \
                                                    'Ultimate only.'
            optional :milestone_id, type: Integer, desc: 'The ID of a milestone to associate with board'
            optional :labels, type: String, desc: 'Comma-separated list of label names'
            optional :weight, type: Integer, desc: 'The weight of the board'
          end
        end
      end
    end
  end
end
