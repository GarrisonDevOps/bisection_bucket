# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        module ParsingErrors
          BaseError = Class.new(StandardError)
          DeserializationException = Class.new(BaseError)

          class FileEmptyError < BaseError
            def initialize
              super('file empty')
            end
          end

          class DependenciesNotPresentError < BaseError
            def initialize
              super('dependencies not present')
            end
          end

          class UnexpectedFormatOrDependenciesNotPresentError < BaseError
            def initialize
              super('unexpected format or dependencies not present')
            end
          end

          class UnexpectedDependencyVersionTypeError < BaseError
            def initialize(version_type)
              super("unexpected dependency version type `#{version_type}`")
            end
          end

          class UnexpectedDependencyNameTypeError < BaseError
            def initialize(name_type)
              super("unexpected dependency name type `#{name_type}`")
            end
          end

          class BlankDependencyNameError < BaseError
            def initialize
              super('dependency name is blank')
            end
          end

          class UnexpectedNodeError < BaseError
            def initialize
              super('encountered unexpected node')
            end
          end
        end
      end
    end
  end
end
