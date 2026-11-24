# frozen_string_literal: true

module Geo
  # Generates the Geo SSF (self-service framework) boilerplate for a new blob (CarrierWave-backed)
  # replicator. See the USAGE file or run `rails g geo:blob_replicator --help`.
  #
  # Two flavors: a regular blob that wires an existing model in place (the base default), and an
  # --upload-partition blob that generates a dedicated read-only model for an upload partition
  # table. All partition-specific behavior lives here; the base stays partition-agnostic.
  class BlobReplicatorGenerator < ReplicatorGenerator
    source_root File.expand_path('templates', __dir__)

    desc 'Generates Geo SSF replication and verification boilerplate for a new blob replicator.'

    class_option :upload_partition, type: :boolean, default: false,
      desc: 'Generate a dedicated read-only model for an upload partition table'
    class_option :parent_factory, type: :string,
      desc: "Parent model factory in upload-partition mode (defaults to NAME minus '_upload')"
    class_option :no_sharding_key, type: :boolean, default: false,
      desc: 'Cell-setting/instance-wide upload partition with no sharding key (e.g. ' \
        'appearance_uploads). The states table is gitlab_main_cell_setting and the replicable ' \
        'is always replicated regardless of selective sync. Requires --upload-partition.'

    private

    def upload_partition?
      options[:upload_partition]
    end

    def no_sharding_key?
      options[:no_sharding_key]
    end

    def sharding_key_optional?
      no_sharding_key?
    end

    def state_gitlab_schema
      no_sharding_key? ? 'gitlab_main_cell_setting' : super
    end

    def extra_validation_errors
      return super unless no_sharding_key?

      errors = super
      errors << '--no-sharding-key requires --upload-partition' unless upload_partition?
      errors << '--no-sharding-key cannot be combined with --sharding-key' if sharding_keys.any?
      errors
    end

    def model_class_required?
      !upload_partition?
    end

    def model_class
      super || (upload_partition? ? class_name : nil)
    end

    def naming
      @naming ||= ::Geo::Replicator::Naming.new(
        file_name: file_name, class_name: class_name, model_class: model_class,
        upload_partition: upload_partition?, parent_factory: options[:parent_factory]
      )
    end

    # Upload partitions generate a dedicated read-only model; regular blobs wire the existing one.
    def create_model
      return super unless upload_partition?

      template 'models/upload_partition_model.rb.tt', "ee/app/models/geo/#{file_name}.rb"
    end

    def create_type_specific_files
      return unless upload_partition?

      template 'migrations/partition_unique_index.rb.tt',
        "db/migrate/#{partition_index_timestamp}_add_unique_index_on_#{table_name}_id.rb"
    end

    def create_factories
      super
      return unless upload_partition?

      template 'factories/upload_partition_model.rb.tt', "ee/spec/factories/geo/#{file_name}.rb"
    end

    def create_specs
      super
      return unless upload_partition?

      template 'specs/upload_partition_model_spec.rb.tt', "ee/spec/models/geo/#{file_name}_spec.rb"
    end

    def type_specific_ruby_files
      return super unless upload_partition?

      [
        "ee/app/models/geo/#{file_name}.rb",
        "ee/spec/models/geo/#{file_name}_spec.rb",
        "ee/spec/factories/geo/#{file_name}.rb",
        "db/migrate/#{partition_index_timestamp}_add_unique_index_on_#{table_name}_id.rb"
      ]
    end

    def print_model_next_steps
      super unless upload_partition?
    end

    def replicator_spec_template
      upload_partition? ? 'specs/upload_partition_replicator_spec.rb.tt' : super
    end

    # -- Model references (partition flavor) --------------------------------

    def replicator_model_reference
      upload_partition? ? "::Geo::#{class_name}" : super
    end

    def registry_belongs_to_class
      upload_partition? ? "Geo::#{class_name}" : super
    end

    def registry_model_class_reference
      upload_partition? ? "::Geo::#{class_name}" : super
    end

    def state_belongs_to_class
      upload_partition? ? "Geo::#{class_name}" : super
    end

    # rubocop:disable Layout/LineLength -- mirrors the generated migration line, which exceeds 120 chars.
    def state_fk_lines
      return super unless upload_partition?

      ["add_concurrent_foreign_key :#{state_table_name}, :#{table_name}, column: :#{foreign_key_name}, on_delete: :cascade"] + super
    end
    # rubocop:enable Layout/LineLength

    def state_inline_foreign_key
      upload_partition? ? '' : super
    end

    # -- Template fragments (partition flavor) ------------------------------

    def replicator_strategy_includes
      upload_partition? ? "    include ::Geo::Concerns::UploadReplicatorBehavior\n" : super
    end

    def registry_partition_includes
      upload_partition? ? "    include ::Geo::PartitionUploadRegistry\n" : super
    end

    def registry_extra_columns
      columns = "      t.text :blob_path, limit: 1024\n"
      columns += "      t.text :uploader_class, limit: 255\n" if upload_partition?
      columns
    end

    def registry_partition_class_methods
      return super unless upload_partition?

      "\n    def self.model_updated_last\n      :created_at\n    end\n"
    end

    def registry_shared_examples
      return super unless upload_partition?

      "#{super}\n  include_examples 'a Geo framework partition upload registry'"
    end

    # -- Upload-partition anchors / timestamps ------------------------------

    # rubocop:disable Layout/LineLength -- mirrors the generated worker-spec lines, which exceed 120 chars.
    def worker_spec_anchors
      return super unless upload_partition?

      {
        create: 'abuse_report_upload = create(:geo_abuse_report_upload)',
        pre: 'expect(Geo::AbuseReportUploadRegistry.where(abuse_report_upload_id: abuse_report_upload.id).count).to eq(0)',
        post: 'expect(Geo::AbuseReportUploadRegistry.where(abuse_report_upload_id: abuse_report_upload.id).count).to eq(1)',
        creation: "        #{file_name} = create(:geo_#{model_factory_name})"
      }
    end
    # rubocop:enable Layout/LineLength

    # The partition-unique-index migration must sort before the states migration so the index
    # exists before the state table's FK references it.
    def partition_index_timestamp
      (base_time - 1).strftime('%Y%m%d%H%M%S')
    end

    def table_name_camel
      table_name.split('_').map(&:capitalize).join
    end
  end
end
