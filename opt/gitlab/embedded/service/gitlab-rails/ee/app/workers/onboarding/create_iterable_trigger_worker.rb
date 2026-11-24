# frozen_string_literal: true

module Onboarding
  class CreateIterableTriggerWorker
    include ApplicationWorker

    CreateIterableTriggerError = Class.new(StandardError)

    deduplicate :until_executed
    data_consistency :delayed

    idempotent!

    feature_category :onboarding

    def perform(iterable_params)
      result = ::Onboarding::CreateIterableTriggerService.new.execute(iterable_params)
      return if result.success?

      logger.error(
        structured_payload(
          params: { iterable_params: iterable_params },
          message: result.errors
        )
      )

      raise CreateIterableTriggerError
    end
  end
end
