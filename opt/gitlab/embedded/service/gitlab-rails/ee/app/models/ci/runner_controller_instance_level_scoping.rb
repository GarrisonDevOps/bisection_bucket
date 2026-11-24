# frozen_string_literal: true

module Ci
  class RunnerControllerInstanceLevelScoping < Ci::ApplicationRecord
    self.table_name = 'ci_runner_controller_instance_level_scopings'

    belongs_to :runner_controller,
      class_name: 'Ci::RunnerController',
      inverse_of: :instance_level_scoping
  end
end
