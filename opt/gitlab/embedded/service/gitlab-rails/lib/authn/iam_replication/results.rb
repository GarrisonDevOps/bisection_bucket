# frozen_string_literal: true

module Authn
  module IamReplication
    # Outcomes a replicator returns. The values are logged, so changing one breaks log queries.
    module Results
      DELIVERED = :delivered
      SKIPPED = :skipped
      ERROR = :error
      FAILED_PRECONDITION = :failed_precondition
      INVALID_REQUEST = :invalid_request
    end
  end
end
