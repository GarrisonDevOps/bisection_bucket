# frozen_string_literal: true

module Gitlab
  module Encryption
    module DbKeyBaseRotation
      # An attr_encrypted attribute, re-encrypted from its stored columns.
      #
      # It works on raw column values and never instantiates the model, so
      # callbacks that assign encrypted attributes (for example
      # `Integration#initialize_properties`) can't run. The plaintext bytes are
      # re-encrypted as they are, without a Marshal or JSON round trip.
      class AttrEncryptedColumn
        SUPPORTED_MODES = %i[per_attribute_iv per_attribute_iv_and_salt].freeze
        MAX_ENCRYPT_ATTEMPTS = 5

        attr_reader :attribute

        # @param model [Class] the model declaring the attribute
        # @param attribute [Symbol] the attr_encrypted attribute
        # @return [Boolean] whether the attribute is encrypted with a `db_key_base` key in a supported mode
        def self.supported?(model, attribute)
          options = model.attr_encrypted_encrypted_attributes.fetch(attribute)

          Gitlab::EncryptedAttribute::DB_KEY_BASE_KEY_TYPES.include?(options[:key]) &&
            SUPPORTED_MODES.include?(options[:mode]) &&
            options[:if] == true && options[:unless] == false
        end

        # @param model [Class] the model declaring the attribute
        # @param attribute [Symbol] the attr_encrypted attribute
        def initialize(model, attribute)
          @model = model
          @attribute = attribute
          @options = model.attr_encrypted_encrypted_attributes.fetch(attribute)
        end

        # @return [Array<String>] the stored columns: the ciphertext, the IV and, when used, the salt
        def columns
          [encrypted_column, iv_column, salt_column].compact
        end

        # @return [Hash] the options that must match for two declarations to share a column
        def definition
          options
        end

        # Re-encrypts the stored value with the current key when an older key decrypts it.
        #
        # @param values [Hash{String => String, nil}] the stored values of {#columns}
        # @return [Hash{String => String}, nil] the new values of {#columns}, or nil when the value is
        #   empty or already on the current key
        # @raise [OpenSSL::Cipher::CipherError] when no key decrypts the value
        # @raise [Gitlab::EncryptedAttribute::AmbiguousDecryptionError] when several keys decrypt it
        def reencrypt(values)
          encrypted_value = values[encrypted_column]
          return unless model.not_empty?(encrypted_value)

          decryption_options = stored_options(values)
          _, key_used, key = model.attr_encrypted_decrypt_with_keys(
            attribute, encrypted_value, decryption_options, decryption_keys)
          return unless key_used == :previous

          plaintext = decrypt_bytes(encrypted_value, decryption_options.merge(key: key))
          encrypt(plaintext)
        end

        private

        attr_reader :model, :options

        # A new CBC value that an older key also seems to decrypt would be ambiguous for the
        # application until that key is removed, so it's encrypted again with a new IV and salt.
        def encrypt(plaintext)
          MAX_ENCRYPT_ATTEMPTS.times do
            new_values = encrypt_with_new_iv(plaintext)
            return new_values if readable?(new_values, plaintext)
          end

          raise OpenSSL::Cipher::CipherError, "#{model.name}##{attribute} doesn't decrypt after re-encryption"
        end

        def encrypt_with_new_iv(plaintext)
          iv = OpenSSL::Cipher.new(options[:algorithm]).tap(&:encrypt).random_iv
          encryption_options = options.merge(key: current_key, iv: iv, marshal: false, allow_empty_value: true)
          new_values = { iv_column => encode(iv, options[:encode_iv]) }

          if salt_column
            salt = SecureRandom.random_bytes
            encryption_options[:salt] = salt
            new_values[salt_column] = options[:encode_salt] ? "_#{encode(salt, options[:encode_salt])}" : salt
          end

          new_values[encrypted_column] = model.attr_encrypted_encrypt(attribute, plaintext, encryption_options)
          new_values
        end

        # Whether the application reads the new value with the current key only, as the same bytes.
        def readable?(new_values, plaintext)
          encrypted_value = new_values[encrypted_column]
          decryption_options = stored_options(new_values)
          _, key_used = model.attr_encrypted_decrypt_with_keys(
            attribute, encrypted_value, decryption_options, decryption_keys)

          key_used == :current && decrypt_bytes(encrypted_value, decryption_options).b == plaintext.b
        rescue OpenSSL::Cipher::CipherError, Gitlab::EncryptedAttribute::AmbiguousDecryptionError
          false
        end

        def decrypt_bytes(encrypted_value, decryption_options)
          model.attr_encrypted_decrypt(attribute, encrypted_value, decryption_options.merge(marshal: false))
        end

        # The options attr_encrypted evaluates for a record, built from its stored IV and salt.
        def stored_options(values)
          stored = options.merge(key: current_key, iv: decode(values[iv_column], options[:encode_iv]))
          stored[:salt] = decode_salt(values[salt_column]) if salt_column
          stored
        end

        # Like attr_encrypted, an empty IV or salt counts as none.
        def decode(value, encoding)
          return if value.nil? || value.empty?

          encoding ? value.unpack1(encoding) : value
        end

        def encode(value, encoding)
          encoding ? [value].pack(encoding) : value
        end

        def decode_salt(salt)
          return if salt.nil? || salt.empty?
          return salt unless options[:encode_salt] && salt.start_with?('_')

          salt[1..].unpack1(options[:encode_salt])
        end

        def current_key
          Gitlab::Encryption::KeyProvider[options[:key]].encryption_key.secret
        end

        def decryption_keys
          model.attr_encrypted_decryption_keys(options[:key])
        end

        def encrypted_column
          options[:attribute].to_s
        end

        def iv_column
          "#{encrypted_column}_iv"
        end

        def salt_column
          "#{encrypted_column}_salt" if options[:mode] == :per_attribute_iv_and_salt
        end
      end
    end
  end
end
