# frozen_string_literal: true

module CascadingProjectSettingAttribute
  extend ActiveSupport::Concern
  include Gitlab::Utils::StrongMemoize

  class_methods do
    def locked_namespace_settings(attribute, namespace_ids)
      lock_column = "lock_#{attribute}"

      NamespaceSetting
        .select(:namespace_id, lock_column, attribute)
        .where(namespace_id: namespace_ids, lock_column => true)
    end

    private

    # logic based on the cascading setting logic
    # CascadingNamespaceSettingAttribute
    #
    # Code remove for this module:
    # - logic related to 'lock_#{attribute}', because projects don't need to lock attributes.
    # - logic related to descendants, because projects don't have descendants.
    # - logic related to a `nil` value for the setting, because the first/only
    #   cascading project setting (`duo_features_enabled`) has a db-level not nil constraint.
    def cascading_attr(*attributes)
      attributes.map(&:to_sym).each do |attribute|
        # public methods
        define_attr_reader(attribute)
        define_attr_writer(attribute)
        define_lock_methods(attribute)

        # private methods
        define_validator_methods(attribute)
        define_attr_before_save(attribute)

        validate :"#{attribute}_changeable?"

        before_save :"before_save_#{attribute}", if: -> { will_save_change_to_attribute?(attribute) }
      end
    end

    def define_attr_reader(attribute)
      define_method(attribute) do
        strong_memoize(attribute) do
          next self[attribute] if will_save_change_to_attribute?(attribute)
          next locked_value(attribute) if cascading_attribute_locked?(attribute)
          next self[attribute] unless self[attribute].nil?

          cascaded_value = cascaded_ancestor_value(attribute)
          next cascaded_value unless cascaded_value.nil?

          application_setting_value(attribute)
        end
      end
    end

    def define_attr_writer(attribute)
      define_method("#{attribute}=") do |value|
        return value if read_attribute(attribute).nil? && to_bool(value) == cascaded_ancestor_value(attribute)

        clear_memoization(attribute)
        super(value)
      end
    end

    def define_attr_before_save(attribute)
      # rubocop:disable GitlabSecurity/PublicSend -- model attribute, not user input
      define_method("before_save_#{attribute}") do
        new_value = public_send(attribute)
        return unless public_send("#{attribute}_was").nil? && new_value == cascaded_ancestor_value(attribute)

        write_attribute(attribute, nil)
      end
      # rubocop:enable GitlabSecurity/PublicSend

      private :"before_save_#{attribute}"
    end

    def define_lock_methods(attribute)
      define_method("#{attribute}_locked?") do
        cascading_attribute_locked?(attribute)
      end

      define_method("#{attribute}_locked_by_ancestor?") do
        locked_by_ancestor?(attribute)
      end

      define_method("#{attribute}_locked_by_application_setting?") do
        locked_by_application_setting?(attribute)
      end

      define_method("#{attribute}_locked_ancestor") do
        locked_ancestor(attribute)
      end
    end

    def define_validator_methods(attribute)
      define_method("#{attribute}_changeable?") do
        return unless cascading_attribute_changed?(attribute)
        return unless cascading_attribute_locked?(attribute)

        errors.add(attribute, s_('CascadingSettings|cannot be changed because it is locked by an ancestor'))
      end

      private :"#{attribute}_changeable?"
    end
  end

  # Lets a batch preloader supply this setting's locked ancestor, so `locked_ancestor` skips its query.
  def preload_locked_ancestor(attribute, namespace_setting)
    strong_memoize(locked_ancestor_memo_key(attribute)) { namespace_setting }
  end

  private

  def locked_value(attribute)
    return application_setting_value(attribute) if locked_by_application_setting?(attribute)

    ancestor = locked_ancestor(attribute)
    ancestor.read_attribute(attribute) if ancestor
  end

  def locked_ancestor(attribute)
    return unless direct_ancestor_present?

    strong_memoize(locked_ancestor_memo_key(attribute)) do
      self.class.locked_namespace_settings(attribute, namespace_ancestor_ids).limit(1).load.first
    end
  end

  def locked_ancestor_memo_key(attribute)
    :"#{attribute}_locked_ancestor"
  end

  def locked_by_ancestor?(attribute)
    locked_ancestor(attribute).present?
  end

  def locked_by_application_setting?(attribute)
    Gitlab::CurrentSettings.public_send("lock_#{attribute}") # rubocop:disable GitlabSecurity/PublicSend -- model attribute, not user input
  end

  def cascading_attribute_locked?(attribute)
    locked_by_ancestor?(attribute) || locked_by_application_setting?(attribute)
  end

  def cascading_attribute_changed?(attribute)
    public_send("#{attribute}_changed?") # rubocop:disable GitlabSecurity/PublicSend -- model attribute, not user input
  end

  def cascaded_ancestor_value(attribute)
    return unless direct_ancestor_present?

    NamespaceSetting
      .select(attribute)
      .joins(
        "join unnest(ARRAY[#{namespace_ancestor_ids_joined}]::bigint[]) with ordinality t(namespace_id, ord)
         USING (namespace_id)"
      )
      .where("#{attribute} IS NOT NULL")
      .order('t.ord')
      .limit(1).first&.read_attribute(attribute)
  end

  def application_setting_value(attribute)
    Gitlab::CurrentSettings.public_send(attribute) # rubocop:disable GitlabSecurity/PublicSend -- model attribute, not user input
  end

  def direct_ancestor_present?
    project.group.present?
  end

  def namespace_ancestor_ids_joined
    namespace_ancestor_ids.join(',')
  end

  def namespace_ancestor_ids
    project.project_namespace.ancestor_ids(hierarchy_order: :asc)
  end
  strong_memoize_attr :namespace_ancestor_ids

  def to_bool(value)
    ActiveModel::Type::Boolean.new.cast(value)
  end
end
