# frozen_string_literal: true

module MergeTrains
  class TrainPolicy < BasePolicy
    delegate { @subject.project }
  end
end
