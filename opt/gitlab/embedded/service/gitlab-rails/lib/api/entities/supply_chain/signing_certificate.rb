# frozen_string_literal: true

module API
  module Entities
    module SupplyChain
      class SigningCertificate < Grape::Entity
        expose :id, documentation: {
          type: 'Integer', format: 'int64', example: 1, desc: 'ID of the signing certificate'
        }
        expose :certificate, documentation: {
          type: 'String',
          example: "-----BEGIN CERTIFICATE-----\nMIIBszCCAVqgAwIBAgIUJ...\n-----END CERTIFICATE-----\n",
          desc: 'PEM-encoded certificate authority (CA) certificate, which contains the CA public key'
        }
        expose :active, documentation: {
          type: 'Boolean',
          example: true,
          desc: 'If true, GitLab uses this CA to issue certificates for new attestations'
        }
        expose :expires_at, documentation: {
          type: 'DateTime', example: '2036-10-22T07:08:25.000Z', desc: 'Date and time the certificate expires'
        }
        expose :created_at, documentation: {
          type: 'DateTime', example: '2026-10-22T07:08:25.643Z', desc: 'Date and time the certificate was created'
        }
      end
    end
  end
end
