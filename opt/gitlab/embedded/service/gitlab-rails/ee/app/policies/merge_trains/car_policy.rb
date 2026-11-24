# frozen_string_literal: true

module MergeTrains
  class CarPolicy < BasePolicy
    delegate { @subject.project }

    rule { can?(:read_merge_train) }.enable :read_merge_train_car
    rule { can?(:cancel_pipeline) & can?(:update_merge_request) }.enable :delete_merge_train_car
  end
end
