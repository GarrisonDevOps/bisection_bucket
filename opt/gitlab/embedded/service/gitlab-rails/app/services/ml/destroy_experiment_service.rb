# frozen_string_literal: true

module Ml
  class DestroyExperimentService
    def initialize(experiment)
      @experiment = experiment
    end

    def execute
      destroyed = if Feature.enabled?(:ml_delete_experiments_in_batches, @experiment.project)
                    @experiment.mark_for_deletion
                  else
                    @experiment.destroy
                  end

      if destroyed
        ServiceResponse.success(payload: payload)
      else
        ServiceResponse.error(message: @experiment.errors.full_messages, payload: payload)
      end
    end

    private

    def payload
      { experiment: @experiment }
    end
  end
end
