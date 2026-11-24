# frozen_string_literal: true

module Gitlab
  class SecretDetectionLogger < Gitlab::JsonLogger
    def self.file_name_noext
      'secret_push_protection'
    end
  end
end
