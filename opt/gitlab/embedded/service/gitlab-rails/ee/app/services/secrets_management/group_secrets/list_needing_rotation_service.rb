# frozen_string_literal: true

module SecretsManagement
  module GroupSecrets
    class ListNeedingRotationService < ListService
      include Secrets::ListNeedingRotationServiceHelpers
    end
  end
end
