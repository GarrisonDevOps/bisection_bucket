# frozen_string_literal: true

module RemoteDevelopment
  class LabelsValidator < ActiveModel::EachValidator
    ALPHA_NUMERIC_CHARACTERS = ('a'..'z').to_set + ('A'..'Z').to_set + ('0'..'9').to_set
    MAX_KEY_NAME_LENGTH = 63
    MAX_KEY_PREFIX_LENGTH = 253
    KEY_VALID_CHARACTERS = ALPHA_NUMERIC_CHARACTERS + %w[- _ .].to_set
    MAX_VALUE_LENGTH = 63
    VALUE_VALID_CHARACTERS = ALPHA_NUMERIC_CHARACTERS + %w[- _ .].to_set

    # @param [RemoteDevelopment::WorkspacesAgentConfig] record
    # @param [Symbol] attribute
    # @param [Hash] value
    # @return [void]
    def validate_each(record, attribute, value)
      unless value.is_a?(Hash)
        record.errors.add(attribute, _("must be an hash"))
        return
      end

      value.each do |k, v|
        validate_label_key(record, attribute, k)
        validate_label_value(record, attribute, v)
      end

      nil
    end

    private

    # @param [RemoteDevelopment::WorkspacesAgentConfig] record
    # @param [Symbol] attribute
    # @param [String] key
    # @return [void]
    def validate_label_key(record, attribute, key)
      unless key.is_a?(String)
        record.errors.add(
          attribute,
          format(_("key: %{key} must be a string"), key: key)
        )
        return
      end

      # Valid label keys have two segments: an optional prefix and name, separated by a slash (/).
      # https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
      prefix = ""
      name = key
      prefix, _, name = key.partition("/") if key.include?("/") && key[0] != "/"

      unless valid_name?(name)
        record.errors.add(
          attribute,
          format(
            _("key: %{key} must have name component with 63 characters or less, " \
              "and start/end with an alphanumeric character"),
            key: key
          )
        )
      end

      unless valid_prefix?(prefix)
        record.errors.add(
          attribute,
          format(
            _("key: %{key} must have prefix component with 253 characters or less, " \
              "and have a valid DNS subdomain as a prefix"),
            key: key)
        )
      end

      return unless prefix.ends_with?("gitlab.com") || prefix.ends_with?("kubernetes.io") || prefix.ends_with?("k8s.io")

      record.errors.add(
        attribute,
        format(_("key: %{key} is reserved for internal usage"), key: key)
      )

      nil
    end

    # @param [RemoteDevelopment::WorkspacesAgentConfig] record
    # @param [Symbol] attribute
    # @param [String] value
    # @return [void]
    def validate_label_value(record, attribute, value)
      unless value.is_a?(String)
        record.errors.add(
          attribute,
          format(_("value: %{value} must be a string"), value: value)
        )
        return
      end

      return if valid_value?(value)

      record.errors.add(
        attribute,
        format(
          _("value: %{value} must be 63 characters or less, and start/end with an alphanumeric character"),
          value: value
        )
      )

      nil
    end

    # @param [String] name
    # @return [Boolean]
    def valid_name?(name)
      return false if name.empty? || name.length > MAX_KEY_NAME_LENGTH
      return false unless alphanumeric?(name[0].to_s) && alphanumeric?(name[-1].to_s)

      name.chars.all? { |char| KEY_VALID_CHARACTERS.include?(char) }
    end

    # @param [String] prefix
    # @return [Boolean]
    def valid_prefix?(prefix)
      return true if prefix.empty?
      return false if prefix.length > MAX_KEY_PREFIX_LENGTH
      return false unless alphanumeric?(prefix[0].to_s) && alphanumeric?(prefix[-1].to_s)

      labels = prefix.split(".")
      labels.all? { |label| valid_dns_label?(label) }
    end

    # @param [String] label
    # @return [Boolean]
    def valid_dns_label?(label)
      return false if label.empty? || label.length > 63

      alphanumeric?(label[0].to_s) && alphanumeric?(label[-1].to_s) &&
        label.chars.all? { |char| alphanumeric?(char) || char == '-' }
    end

    # @param [String] value
    # @return [Boolean]
    def valid_value?(value)
      return true if value.empty?
      return false if value.length > MAX_VALUE_LENGTH
      return false unless alphanumeric?(value[0].to_s) && alphanumeric?(value[-1].to_s)

      value.chars.all? { |char| VALUE_VALID_CHARACTERS.include?(char) }
    end

    # @param [String] char
    # @return [Boolean]
    def alphanumeric?(char)
      ALPHA_NUMERIC_CHARACTERS.include?(char)
    end
  end
end
