# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module WorkloadCredential
      # The maximum the instance-wide oauth_access_token_expires_in setting may take. Workload
      # credentials are pinned to it explicitly, not read from the configured value, and callers
      # are clamped to it below.
      EXPIRES_IN = ::ApplicationSetting::DEFAULT_OAUTH_ACCESS_TOKEN_EXPIRES_IN.seconds
    end
  end
end
