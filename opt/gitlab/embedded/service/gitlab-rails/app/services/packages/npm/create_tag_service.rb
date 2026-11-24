# frozen_string_literal: true

module Packages
  module Npm
    class CreateTagService
      include Gitlab::Utils::StrongMemoize

      attr_reader :package, :tag_name

      def initialize(package, tag_name)
        @package = package
        @tag_name = tag_name
      end

      def execute
        return success(existing_tag, changed: false) if existing_tag&.package_id == package.id

        tag = if existing_tag.present?
                existing_tag.update_column(:package_id, package.id)
                existing_tag
              else
                package.tags.create!(name: tag_name)
              end

        success(tag, changed: true)
      end

      private

      def success(tag, changed:)
        ServiceResponse.success(payload: { tag: tag, changed: changed })
      end

      def existing_tag
        Packages::TagsFinder
            .new(package.project, package.name, ::Packages::Npm::Package)
            .find_by_name(tag_name)
      end
      strong_memoize_attr :existing_tag
    end
  end
end
