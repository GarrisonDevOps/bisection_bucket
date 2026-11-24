# frozen_string_literal: true

module ArtifactRegistry
  class ConnectionTestResult < ValueObject
    include TimeCoercion

    expose_attribute :http_status, :last_health_status

    def passed
      @attributes['passed'] == true
    end

    def last_health_checked_at
      parse_time(@attributes['last_health_checked_at'])
    end
  end
end
