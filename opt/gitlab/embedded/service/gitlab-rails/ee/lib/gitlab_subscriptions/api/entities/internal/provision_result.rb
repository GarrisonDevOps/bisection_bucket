# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Entities
      module Internal
        class ProvisionResult < Grape::Entity
          expose :status, documentation: { type: 'String', example: 'success' }
          expose :message, documentation: { type: 'String', example: 'Namespace provisioned successfully' }
          expose :payload, documentation: {
            type: 'Hash',
            properties: {
              base_product: {
                type: 'object',
                properties: {
                  status: { type: 'string', enum: %w[success error] },
                  message: { type: 'string', description: 'Message when status is error' }
                },
                description: 'Base product provisioning result'
              },
              storage: {
                type: 'object',
                properties: {
                  status: { type: 'string', enum: %w[success error] },
                  message: { type: 'string', description: 'Message when status is error' }
                },
                description: 'Storage provisioning result'
              },
              compute_minutes: {
                type: 'object',
                properties: {
                  status: { type: 'string', enum: %w[success error] },
                  message: { type: 'string', description: 'Message when status is error' }
                },
                description: 'Compute minutes provisioning result'
              },
              add_on_purchases: {
                type: 'object',
                properties: {
                  status: { type: 'string', enum: %w[success error] },
                  message: { type: 'string', description: 'Message when status is error' }
                },
                description: 'Add-on purchases provisioning result'
              }
            },
            example: {
              base_product: { status: 'success' },
              storage: { status: 'success' },
              compute_minutes: { status: 'error',
                                 message: 'Validation failed: Compute Minutes limit must be positive' },
              add_on_purchases: { status: 'success' }
            }
          }
        end
      end
    end
  end
end
