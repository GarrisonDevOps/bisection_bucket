# frozen_string_literal: true

module API
  module Entities
    class PagesDomainCertificateExpiration < Grape::Entity
      expose :expired?, as: :expired, documentation: { type: 'Boolean' }
      expose :expiration, documentation: { type: 'DateTime', example: '2025-01-01T00:00:00.000Z' }
    end
  end
end
