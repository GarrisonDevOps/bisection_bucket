# frozen_string_literal: true

module Gitlab
  module ExternallyStoredField
    extend ActiveSupport::Concern

    included do
      include FileStoreMounter

      class_attribute :externally_stored_payloads, default: {}.freeze
      class_attribute :externally_stored_field_payloads, default: {}.freeze

      after_commit :store_external_payloads, on: [:create, :update]
    end

    class_methods do
      def mount_external_storage(klass)
        if externally_stored_payloads.empty?
          raise ArgumentError, 'no externally stored fields declared yet; mount_external_storage must come last'
        end

        externally_stored_payloads.each_key do |payload|
          mount_file_store_uploader klass, skip_store_file: true, file_field: :"#{payload}_file"
          skip_callback :commit, :after, :"remove_#{payload}_file!"
        end

        after_commit :remove_external_payloads, on: :destroy
      end

      def externally_stored_field(field, payload: field)
        field = field.to_sym
        payload = payload.to_sym

        fields = externally_stored_payloads.fetch(payload, Set.new) | [field]
        self.externally_stored_payloads = externally_stored_payloads.merge(payload => fields).freeze
        self.externally_stored_field_payloads = externally_stored_field_payloads.merge(field => payload).freeze

        attribute field, :string

        # Without loading first, the generated writer compares against an in-memory original of
        # nil, so clearing a field that has stored content would not register as a change.
        define_method(:"#{field}=") do |value|
          load_external_payload(payload)
          super(value)
        end
      end
    end

    def external_payload_filename(payload)
      "#{payload}.json"
    end

    def external_payload_stored?(payload)
      self[:"#{payload}_file"].present?
    end

    def externally_stored_field?(field_name)
      externally_stored_field_payloads.key?(field_name.to_sym)
    end

    def reload(*)
      self.loaded_external_payloads = nil

      super
    end

    # `[]` goes through `read_attribute` and AR's generated readers through `_read_attribute`,
    # and the two do not call each other, so lazy loading has to hook both.
    def read_attribute(attr_name)
      ensure_external_payload_loaded(attr_name)
      super
    end

    def _read_attribute(attr_name)
      ensure_external_payload_loaded(attr_name)
      super
    end

    private

    attr_accessor :loaded_external_payloads

    def ensure_external_payload_loaded(attr_name)
      payload = externally_stored_field_payloads[attr_name.to_sym]
      load_external_payload(payload) if payload
    end

    def load_external_payload(payload)
      self.loaded_external_payloads ||= Set.new
      return unless loaded_external_payloads.add?(payload)
      return unless persisted?

      document = read_external_payload(payload)
      return unless document

      # `write_from_database` records these as the original values, so later writes are dirty
      # tracked against them. No public API has those semantics.
      externally_stored_payloads.fetch(payload).each do |field|
        # rubocop:disable Gitlab/ModuleWithInstanceVariables -- interacting with AR internals
        @attributes.write_from_database(field.to_s, document[field.to_s])
        # rubocop:enable Gitlab/ModuleWithInstanceVariables
      end
    end

    def payload_uploader(payload)
      public_send(:"#{payload}_file") # rubocop:disable GitlabSecurity/PublicSend -- mount_uploader reader
    end

    def read_external_payload(payload)
      uploader = payload_uploader(payload)

      # The mounted uploader is nil until a payload has been stored, and the Fog backend
      # fails with NoMethodError (!) rather than returning false when the object is missing.
      return unless uploader&.file&.exists?

      Gitlab::Json.safe_parse(uploader.read)
    rescue JSON::ParserError
      nil
    end

    def build_external_payload(payload)
      externally_stored_payloads.fetch(payload).each_with_object({}) do |field, document|
        document[field.to_s] = read_attribute(field)
      end
    end

    # The `updates:` path is a read-merge-write. Concurrent calls touching different fields of
    # one payload can clobber each other; there is no locking.
    def persist_external_payload(payload, updates: nil)
      merging = updates && persisted?
      # Read only to merge, which makes the comparison below free. The other path has nothing
      # read to compare against and only runs when a field changed, so it writes unconditionally.
      stored = read_external_payload(payload) if merging
      document = merging ? (stored || {}).merge(updates) : build_external_payload(payload)

      if document.values.all?(&:blank?)
        remove_external_payload(payload)
      elsif !merging || document != stored
        write_external_payload(payload, document)
      end
    end

    def persist_external_payload_updates(updates)
      updates
        .group_by { |field, _| externally_stored_field_payloads.fetch(field.to_sym) }
        .each { |payload, pairs| persist_external_payload(payload, updates: pairs.to_h) }
    end

    def write_external_payload(payload, document)
      file_field = :"#{payload}_file"
      filename = self[file_field].presence || external_payload_filename(payload)

      # rubocop:disable GitlabSecurity/PublicSend -- mount_file_store_uploader writer and store hook
      public_send(:"#{file_field}=", CarrierWaveStringFile.new_file(
        file_content: Gitlab::Json.dump(document),
        filename: filename,
        content_type: 'application/json'
      ))
      public_send(:"store_#{file_field}_now!")
      # rubocop:enable GitlabSecurity/PublicSend

      update_column(file_field, payload_uploader(payload).identifier)
    end

    def remove_external_payload(payload)
      file_field = :"#{payload}_file"
      return if self[file_field].blank?

      # The column can name a document that was never written, and Fog raises on a missing
      # object rather than reporting it.
      uploader = payload_uploader(payload)
      public_send(:"remove_#{file_field}!") if uploader&.file&.exists? # rubocop:disable GitlabSecurity/PublicSend -- mount_uploader remover

      update_column(file_field, nil)
    end

    def store_external_payloads
      externally_stored_payloads.each do |payload, fields|
        next unless fields.any? { |field| saved_change_to_attribute?(field) }

        persist_external_payload(payload)
      end
    end

    def remove_external_payloads
      externally_stored_payloads.each_key { |payload| remove_external_payload_on_destroy(payload) }
    end

    def remove_external_payload_on_destroy(payload)
      public_send(:"remove_#{payload}_file!") # rubocop:disable GitlabSecurity/PublicSend -- mount_uploader remover
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e)
    end
  end
end
