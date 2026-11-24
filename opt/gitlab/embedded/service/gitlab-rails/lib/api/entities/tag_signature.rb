# frozen_string_literal: true

module API
  module Entities
    class TagSignature < Grape::Entity
      expose :signature_type, documentation: {
        type: 'String', example: 'PGP', values: %w[PGP X509 SSH],
        desc: 'Type of signature. Signature details are returned only for `X509`.'
      }

      expose :signature, merge: true, documentation: { type: 'Hash' } do |tag|
        ::API::Entities::X509Signature.represent tag.signature if tag.signature_type == :X509
      end
    end
  end
end
