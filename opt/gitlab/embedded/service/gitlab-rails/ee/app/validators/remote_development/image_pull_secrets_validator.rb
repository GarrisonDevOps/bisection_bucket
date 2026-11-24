# frozen_string_literal: true

module RemoteDevelopment
  class ImagePullSecretsValidator < ActiveModel::EachValidator
    # @param [RemoteDevelopment::WorkspacesAgentConfig] record
    # @param [Symbol] attribute
    # @param [Hash] value
    # @return [void]
    def validate_each(record, attribute, value)
      return if record.errors[attribute].any?

      image_pull_secret_names = value.map { |image_pull_secret| image_pull_secret.deep_symbolize_keys.fetch(:name) }
      image_pull_secret_names_duplicates = image_pull_secret_names.tally.select { |_, count| count > 1 }.keys
      image_pull_secret_names_duplicates.each do |image_pull_secret_duplicate_name|
        record.errors.add(
          attribute,
          format(
            _("name: %{name} exists in more than one image pull secret, " \
              "image pull secrets must have a unique 'name'"),
            name: image_pull_secret_duplicate_name)
        )
      end

      nil
    end
  end
end
