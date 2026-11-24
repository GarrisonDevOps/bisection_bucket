# frozen_string_literal: true

module SecretsManagement
  module ProjectSecrets
    class ListNeedingRotationService < ListService
      include Secrets::ListNeedingRotationServiceHelpers
    end
  end
end
