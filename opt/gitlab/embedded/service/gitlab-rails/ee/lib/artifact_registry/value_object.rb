# frozen_string_literal: true

module ArtifactRegistry
  # Readers that coerce or filter stay hand-written in the subclass.
  class ValueObject
    # Defines a public reader per name that returns the raw value under its string key.
    # Readers stay public even under `private` in the subclass body.
    def self.expose_attribute(*names)
      names.each do |name|
        key = name.to_s
        define_method(name) { @attributes[key] }
      end
    end
    private_class_method :expose_attribute

    def initialize(attributes = {})
      @attributes = attributes || {}
    end
  end
end
