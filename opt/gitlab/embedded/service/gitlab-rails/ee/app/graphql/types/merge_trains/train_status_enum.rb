# frozen_string_literal: true

module Types
  module MergeTrains
    class TrainStatusEnum < BaseEnum
      graphql_name 'MergeTrainStatus'

      ::MergeTrains::Train::STATUSES.each_value do |status|
        value status.upcase, value: status, description: "#{status.capitalize} merge train."
      end
    end
  end
end
