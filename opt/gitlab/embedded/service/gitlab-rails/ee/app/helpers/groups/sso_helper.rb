# frozen_string_literal: true

module Groups::SsoHelper
  extend self

  def saml_provider_enabled?(group = nil)
    return false unless group.is_a? Group

    !!group.root_ancestor.saml_provider&.enabled?
  end
end
