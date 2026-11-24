# frozen_string_literal: true

module AuditEvents
  module Streaming
    module HTTP
      module NamespaceFilterable
        extend ActiveSupport::Concern

        included do
          validate :ensure_namespace_type, if: -> { namespace.present? }
        end

        private

        def ensure_namespace_type
          return if namespace.is_a?(::Namespaces::ProjectNamespace) || namespace.is_a?(::Group)

          errors.add(:namespace, 'is not supported. Only project and group are supported.')
        end
      end
    end
  end
end
