# frozen_string_literal: true

module EE
  module JsonSchemaValidator
    private

    def schema_path
      ce_path = super
      ee_path = Rails.root.join('ee', *base_directory, filename_with_extension)

      existing_path = [ee_path, ce_path].detect { |path| File.exist?(path) }

      raise "No json validation schema `#{filename_with_extension}` found" unless existing_path

      existing_path
    end
  end
end
