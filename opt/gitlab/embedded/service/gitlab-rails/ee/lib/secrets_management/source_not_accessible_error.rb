# frozen_string_literal: true

module SecretsManagement
  # Raised (not just returned as an empty payload) so the caller can drop the build with the right reason.
  SourceNotAccessibleError = Class.new(StandardError)
end
