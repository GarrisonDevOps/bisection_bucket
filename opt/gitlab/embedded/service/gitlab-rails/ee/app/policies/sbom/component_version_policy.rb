# frozen_string_literal: true

module Sbom
  class ComponentVersionPolicy < BasePolicy
    rule { default }.enable :read_component_version
  end
end
