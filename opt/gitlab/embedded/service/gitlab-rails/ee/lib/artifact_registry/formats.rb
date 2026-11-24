# frozen_string_literal: true

module ArtifactRegistry
  module Formats
    Format = Data.define(:name, :collection, :package_class, :file_class)

    REGISTRY = [
      Format.new(name: 'maven', collection: 'packages', package_class: MavenPackage, file_class: MavenFile),
      Format.new(name: 'npm', collection: 'packages', package_class: NpmPackage, file_class: NpmFile),
      Format.new(name: 'docker', collection: 'images', package_class: nil, file_class: nil),
      Format.new(name: 'oci', collection: 'images', package_class: nil, file_class: nil)
    ].index_by(&:name).freeze

    PACKAGE_FORMATS = REGISTRY.values.select { |format| format.collection == 'packages' }.map(&:name).freeze
    IMAGE_FORMATS = REGISTRY.values.select { |format| format.collection == 'images' }.map(&:name).freeze
    ARTIFACT_FORMATS = (PACKAGE_FORMATS + IMAGE_FORMATS).freeze

    class << self
      def package_class(format)
        fetch(format, PACKAGE_FORMATS, :package_class)
      end

      def file_class(format)
        fetch(format, PACKAGE_FORMATS, :file_class)
      end

      def collection(format)
        fetch(format, ARTIFACT_FORMATS, :collection)
      end

      private

      def fetch(format, allowed, attribute)
        value = REGISTRY[format].to_h[attribute] if allowed.include?(format)
        value || raise(ArgumentError, "format must be one of: #{allowed.join(', ')}")
      end
    end
  end
end
