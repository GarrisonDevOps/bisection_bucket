# frozen_string_literal: true

module ArtifactRegistry
  class NamespaceConnectionTestResult < ValueObject
    expose_attribute :http_status

    def passed
      @attributes['passed'] == true
    end
  end
end
